#![expect(deprecated)]

use std::{borrow::Borrow, collections::HashSet};

use axum::extract::State;
use futures::{FutureExt, StreamExt, TryFutureExt, TryStreamExt, future::try_join4};
use ruma::{
	OwnedEventId, OwnedRoomId, OwnedServerName, OwnedUserId, RoomId, ServerName,
	api::federation::membership::create_join_event,
	events::{
		StateEventType,
		room::member::{MembershipState, RoomMemberEventContent},
	},
};
use serde_json::value::RawValue as RawJsonValue;
use tuwunel_core::{
	Err, Result, at, err,
	itertools::Itertools,
	matrix::{Event, event::gen_event_id_canonical_json},
	utils::stream::{BroadbandExt, IterStream, TryBroadbandExt},
	warn,
};
use tuwunel_service::{Services, rooms::short::ShortStateKey};

use crate::Ruma;

/// helper method for /send_join v1 and v2
async fn create_join_event(
	services: &Services,
	origin: &ServerName,
	room_id: &RoomId,
	pdu: &RawJsonValue,
	omit_members: bool,
) -> Result<create_join_event::v1::RoomState> {
	if !services.metadata.exists(room_id).await {
		return Err!(Request(NotFound("Room is unknown to this server.")));
	}

	// ACL check origin server
	services
		.event_handler
		.acl_check(origin, room_id)
		.await?;

	// We need to return the state prior to joining, let's keep a reference to that
	// here
	let shortstatehash = services
		.state
		.get_room_shortstatehash(room_id)
		.await
		.map_err(|e| err!(Request(NotFound(error!("Room has no state: {e}")))))?;

	// We do not add the event_id field to the pdu here because of signature and
	// hashes checks
	let room_version = services.state.get_room_version(room_id).await?;

	let Ok((event_id, mut value)) = gen_event_id_canonical_json(pdu, &room_version) else {
		// Event could not be converted to canonical json
		return Err!(Request(BadJson("Could not convert event to canonical json.")));
	};

	let event_room_id: OwnedRoomId = serde_json::from_value(
		value
			.get("room_id")
			.ok_or_else(|| err!(Request(BadJson("Event missing room_id property."))))?
			.clone()
			.into(),
	)
	.map_err(|e| err!(Request(BadJson(warn!("room_id field is not a valid room ID: {e}")))))?;

	if event_room_id != room_id {
		return Err!(Request(BadJson("Event room_id does not match request path room ID.")));
	}

	let event_type: StateEventType = serde_json::from_value(
		value
			.get("type")
			.ok_or_else(|| err!(Request(BadJson("Event missing type property."))))?
			.clone()
			.into(),
	)
	.map_err(|e| err!(Request(BadJson(warn!("Event has invalid state event type: {e}")))))?;

	if event_type != StateEventType::RoomMember {
		return Err!(Request(BadJson(
			"Not allowed to send non-membership state event to join endpoint."
		)));
	}

	let content: RoomMemberEventContent = serde_json::from_value(
		value
			.get("content")
			.ok_or_else(|| err!(Request(BadJson("Event missing content property"))))?
			.clone()
			.into(),
	)
	.map_err(|e| err!(Request(BadJson(warn!("Event content is empty or invalid: {e}")))))?;

	if content.membership != MembershipState::Join {
		return Err!(Request(BadJson(
			"Not allowed to send a non-join membership event to join endpoint."
		)));
	}

	// ACL check sender user server name
	let sender: OwnedUserId = serde_json::from_value(
		value
			.get("sender")
			.ok_or_else(|| err!(Request(BadJson("Event missing sender property."))))?
			.clone()
			.into(),
	)
	.map_err(|e| err!(Request(BadJson(warn!("sender property is not a valid user ID: {e}")))))?;

	services
		.event_handler
		.acl_check(sender.server_name(), room_id)
		.await?;

	// check if origin server is trying to send for another server
	if sender.server_name() != origin {
		return Err!(Request(Forbidden("Not allowed to join on behalf of another server.")));
	}

	let state_key: OwnedUserId = serde_json::from_value(
		value
			.get("state_key")
			.ok_or_else(|| err!(Request(BadJson("Event missing state_key property."))))?
			.clone()
			.into(),
	)
	.map_err(|e| err!(Request(BadJson(warn!("State key is not a valid user ID: {e}")))))?;

	if state_key != sender {
		return Err!(Request(BadJson("State key does not match sender user.")));
	}

	if let Some(authorising_user) = content.join_authorized_via_users_server {
		use ruma::RoomVersionId::*;

		if matches!(room_version, V1 | V2 | V3 | V4 | V5 | V6 | V7) {
			return Err!(Request(InvalidParam(
				"Room version {room_version} does not support restricted rooms but \
				 join_authorised_via_users_server ({authorising_user}) was found in the event."
			)));
		}

		if !services.globals.user_is_local(&authorising_user) {
			return Err!(Request(InvalidParam(
				"Cannot authorise membership event through {authorising_user} as they do not \
				 belong to this homeserver"
			)));
		}

		if !services
			.state_cache
			.is_joined(&authorising_user, room_id)
			.await
		{
			return Err!(Request(InvalidParam(
				"Authorising user {authorising_user} is not in the room you are trying to join, \
				 they cannot authorise your join."
			)));
		}

		if !super::user_can_perform_restricted_join(services, &state_key, room_id, &room_version)
			.await?
		{
			return Err!(Request(UnableToAuthorizeJoin(
				"Joining user did not pass restricted room's rules."
			)));
		}
	}

	services
		.server_keys
		.hash_and_sign_event(&mut value, &room_version)
		.map_err(|e| err!(Request(InvalidParam(warn!("Failed to sign send_join event: {e}")))))?;

	let origin: OwnedServerName = serde_json::from_value(
		value
			.get("origin")
			.ok_or_else(|| err!(Request(BadJson("Event does not have an origin server name."))))?
			.clone()
			.into(),
	)
	.map_err(|e| err!(Request(BadJson("Event has an invalid origin server name: {e}"))))?;

	// Prestart state gather here since it doesn't involve the new join event.
	let state_ids = services
		.state_accessor
		.state_full_ids(shortstatehash)
		.collect::<Vec<_>>()
		.boxed()
		.shared();
	// Filter out members if omit_members is true (MSC3706 + MSC3943)
	let filtered_state_ids = if omit_members {
		let joining_user_ssk = services
			.short
			.get_shortstatekey(&StateEventType::RoomMember, state_key.as_str())
			.await
			.ok();

		state_ids
			.clone()
			.then(move |state| {
				let joining_user_ssk = joining_user_ssk;
				async move {
					// MSC3943: Only include heroes when the room has no name and no
					// canonical alias (matching Synapse's behavior in PR #14442).
					let has_name = state
						.iter()
						.stream()
						.any(|&(ssk, _)| async move {
							services
								.short
								.get_statekey_from_short(ssk)
								.await
								.is_ok_and(|(et, sk)| {
									et == StateEventType::RoomName && sk.is_empty()
								})
						})
						.await;

					let has_alias = state
						.iter()
						.stream()
						.any(|&(ssk, _)| async move {
							services
								.short
								.get_statekey_from_short(ssk)
								.await
								.is_ok_and(|(et, sk)| {
									et == StateEventType::RoomCanonicalAlias && sk.is_empty()
								})
						})
						.await;

					// Collect hero SSKs only if room has no name and no canonical alias
					let heroes_ssks: HashSet<ShortStateKey> = if !has_name && !has_alias {
						// Classify members by membership state, excluding the joining
						// user (matching Synapse's extract_heroes_from_room_summary).
						let mut joined_invited: Vec<(ShortStateKey, String)> = Vec::new();
						let mut left_banned: Vec<(ShortStateKey, String)> = Vec::new();

						for &(ssk, ref eid) in &state {
							let Ok((et, key)) = services.short.get_statekey_from_short(ssk).await
							else {
								continue;
							};
							if et != StateEventType::RoomMember {
								continue;
							}
							// Exclude the joining user from heroes
							if Some(ssk) == joining_user_ssk {
								continue;
							}
							let Ok(pdu) = services.timeline.get_pdu(eid).await else {
								continue;
							};
							let Ok(content) = serde_json::from_str::<RoomMemberEventContent>(
								pdu.content().get(),
							) else {
								continue;
							};
							match content.membership {
								| MembershipState::Join | MembershipState::Invite => {
									joined_invited.push((ssk, key.to_string()));
								},
								| MembershipState::Leave | MembershipState::Ban => {
									left_banned.push((ssk, key.to_string()));
								},
								| _ => {},
							}
						}

						// Synapse: use joined+invited if any, otherwise fall back to
						// left+banned. Sort by MXID, take first 5.
						let heroes = if !joined_invited.is_empty() {
							joined_invited
						} else {
							left_banned
						};

						heroes
							.into_iter()
							.sorted_by_key(|(_, key)| key.clone())
							.map(|(ssk, _)| ssk)
							.take(5)
							.collect()
					} else {
						HashSet::new()
					};

					// Filter state: keep all non-member events, the joining user's
					// member event, and hero member events. If get_statekey_from_short
					// fails, keep the event (safe default, matching original behavior).
					state
						.iter()
						.stream()
						.broad_filter_map(move |&(ssk, ref eid)| {
							let joining_user_ssk = joining_user_ssk;
							let heroes_ssks = heroes_ssks.clone();
							let eid = eid.clone();
							async move {
								let keep = services
									.short
									.get_statekey_from_short(ssk)
									.await
									.map(|(et, _)| {
										et != StateEventType::RoomMember
											|| Some(ssk) == joining_user_ssk || heroes_ssks
											.contains(&ssk)
									})
									.unwrap_or(true); // safe default: keep unknown events

								keep.then_some(eid)
							}
						})
						.collect::<Vec<OwnedEventId>>()
						.await
				}
			})
			.boxed()
	} else {
		state_ids
			.clone()
			.map(|state| {
				state
					.iter()
					.map(|(_, eid)| eid)
					.cloned()
					.collect::<Vec<_>>()
			})
			.boxed()
	};

	let mutex_lock = services
		.event_handler
		.mutex_federation
		.lock(room_id)
		.await;

	let pdu_id = services
		.event_handler
		.handle_incoming_pdu(&origin, room_id, &event_id, value.clone(), true)
		.boxed()
		.await?
		.map(at!(0))
		.ok_or_else(|| err!(Request(InvalidParam("Could not accept as timeline event."))))?;

	drop(mutex_lock);

	// Join event for new server.
	let event = services
		.federation
		.format_pdu_into(value, Some(&room_version))
		.map(Some)
		.map(Ok);

	// Join event revealed to existing servers.
	let broadcast = services.sending.send_pdu_room(room_id, &pdu_id);

	// Wait for state gather which the remaining operations depend on.
	let state_ids = filtered_state_ids.await;

	let auth_heads = state_ids.iter().map(Borrow::borrow);

	let into_federation_format = |pdu| {
		services
			.federation
			.format_pdu_into(pdu, Some(&room_version))
			.map(Ok)
	};

	let auth_chain_ids: HashSet<OwnedEventId> = services
		.auth_chain
		.event_ids_iter(room_id, &room_version, auth_heads)
		.try_collect()
		.await?;

	let state_ids_set: HashSet<OwnedEventId> = state_ids.iter().cloned().collect();

	let auth_chain = auth_chain_ids
		.into_iter()
		.stream()
		.map(Ok::<_, tuwunel_core::Error>)
		.broad_and_then(async |event_id| {
			// MSC3706: Any events returned within state can be omitted from auth_chain.
			if omit_members && state_ids_set.contains(&event_id) {
				return Ok(None);
			}

			let json_res = services.timeline.get_pdu_json(&event_id).await;

			match json_res {
				| Ok(pdu) => into_federation_format(pdu).await.map(Some),
				| Err(e) => Err(e),
			}
		})
		.try_filter_map(|opt_event| futures::future::ready(Ok(opt_event)))
		.try_collect();
	let state = state_ids
		.iter()
		.try_stream()
		.broad_and_then(|event_id| {
			services
				.timeline
				.get_pdu_json(event_id)
				.and_then(into_federation_format)
		})
		.try_collect();

	let (auth_chain, state, event, ()) = try_join4(auth_chain, state, event, broadcast)
		.boxed()
		.await?;

	Ok(create_join_event::v1::RoomState { auth_chain, state, event })
}

/// # `PUT /_matrix/federation/v1/send_join/{roomId}/{eventId}`
///
/// Submits a signed join event.
pub(crate) async fn create_join_event_v1_route(
	State(services): State<crate::State>,
	body: Ruma<create_join_event::v1::Request>,
) -> Result<create_join_event::v1::Response> {
	if let Some(server) = body.room_id.server_name()
		&& services
			.config
			.forbidden_remote_server_names
			.is_match(server.host())
	{
		warn!(
			"Server {} tried joining room ID {} through us which has a server name that is \
			 globally forbidden. Rejecting.",
			body.origin(),
			&body.room_id,
		);

		return Err!(Request(Forbidden(warn!(
			"Room ID server name {server} is banned on this homeserver."
		))));
	}

	Ok(create_join_event::v1::Response {
		room_state: create_join_event(&services, body.origin(), &body.room_id, &body.pdu, false)
			.boxed()
			.await?,
	})
}

/// # `PUT /_matrix/federation/v2/send_join/{roomId}/{eventId}`
///
/// Submits a signed join event.
pub(crate) async fn create_join_event_v2_route(
	State(services): State<crate::State>,
	body: Ruma<create_join_event::v2::Request>,
) -> Result<create_join_event::v2::Response> {
	if let Some(server) = body.room_id.server_name()
		&& services
			.config
			.forbidden_remote_server_names
			.is_match(server.host())
	{
		warn!(
			"Server {} tried joining room ID {} through us which has a server name that is \
			 globally forbidden. Rejecting.",
			body.origin(),
			&body.room_id,
		);

		return Err!(Request(Forbidden(warn!(
			"Room ID server name {server} is banned on this homeserver."
		))));
	}

	// Get the servers in the room BEFORE the join
	let servers_in_room = if body.omit_members {
		Some(
			services
				.state_cache
				.room_servers(&body.room_id)
				.map(ToString::to_string)
				.collect::<Vec<_>>()
				.await,
		)
	} else {
		None
	};

	let create_join_event::v1::RoomState { auth_chain, state, event } =
		create_join_event(&services, body.origin(), &body.room_id, &body.pdu, body.omit_members)
			.boxed()
			.await?;

	Ok(create_join_event::v2::Response {
		room_state: create_join_event::v2::RoomState {
			members_omitted: body.omit_members,
			auth_chain,
			state,
			event,
			servers_in_room,
		},
	})
}
