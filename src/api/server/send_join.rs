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
	matrix::{Event, event::gen_event_id_canonical_json},
	utils::{
		BoolExt,
		stream::{BroadbandExt, IterStream, ReadyExt, TryBroadbandExt},
	},
	warn,
};
use tuwunel_service::Services;

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
	// Filter out members if omit_members is true
	let filtered_state_ids = if omit_members {
		let joining_user_shortstatekey = services
			.short
			.get_shortstatekey(&StateEventType::RoomMember, state_key.as_str())
			.await
			.ok();

		// Fetch up to 5 heroes to include their member events
		// MSC3706 / MSC3943: Heroes' member events should be included.
		let heroes_ssks = services
			.state_accessor
			.room_state_type_pdus(room_id, &StateEventType::RoomMember)
			.ready_filter_map(Result::ok)
			.ready_filter_map(|pdu| pdu.state_key().map(ToOwned::to_owned))
			.take(5)
			.broad_filter_map(|u| async move {
				services
					.short
					.get_shortstatekey(&StateEventType::RoomMember, u.as_str())
					.await
					.ok()
			})
			.collect::<Vec<_>>()
			.await
			.into_iter()
			.collect::<HashSet<_>>();

		state_ids
			.clone()
			.then(move |state| {
				let joining_user_ssk = joining_user_shortstatekey;
				let heroes_ssks = heroes_ssks;
				async move {
					state
						.iter()
						.stream()
						.broad_filter_map(move |&(ssk, ref eid)| {
							let joining_user_ssk = joining_user_ssk;
							let heroes_ssks = heroes_ssks.clone();
							let eid = eid.clone();
							services
								.short
								.get_statekey_from_short(ssk)
								.map(move |res| {
									let keep = res
										.map(|(et, _)| {
											// Keep if not a member event
											et != StateEventType::RoomMember
											// or if it's the joining user's member event
												|| Some(ssk) == joining_user_ssk
											// or if it's a room hero's member event
												|| heroes_ssks.contains(&ssk)
										})
										.unwrap_or(true);

									keep.then_some(eid)
								})
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

	// Get the auth chain for the new server.
	let mut auth_chain_ids: HashSet<OwnedEventId> = services
		.auth_chain
		.event_ids_iter(room_id, &room_version, auth_heads)
		.try_collect()
		.await?;

	// Remove member events from the auth chain if omit_members is true
	if omit_members {
		for id in &state_ids {
			auth_chain_ids.remove(id);
		}
	}

	let auth_chain = auth_chain_ids
		.into_iter()
		.stream()
		.map(Ok::<_, tuwunel_core::Error>)
		.broad_and_then(async |event_id| {
			services
				.timeline
				.get_pdu_json(&event_id)
				.and_then(into_federation_format)
				.await
		})
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

	// Get the servers in the room if omit_members is true
	let server_in_room = body.omit_members.then_async(|| {
		services
			.state_cache
			.room_servers(&body.room_id)
			.map(ToString::to_string)
			.collect()
	});

	let room_state =
		create_join_event(&services, body.origin(), &body.room_id, &body.pdu, body.omit_members);

	let (servers_in_room, create_join_event::v1::RoomState { auth_chain, state, event }) =
		futures::future::try_join(server_in_room.map(Ok), room_state)
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
