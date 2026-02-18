package diamond.policy.tiled

import data.diamond.policy.admin
import data.diamond.policy.session
import data.diamond.policy.token
import rego.v1

# Assign read & write scopes to clients with tiled-writer audience
# defaults to read-only scopes
default scopes := {
	"read:metadata",
	"read:data",
}

scopes := {
	"read:metadata",
	"read:data",
	"write:metadata",
	"write:data",
	"create:node",
	"register",
} if {
	"tiled-writer" in token.claims.aud
}

_session := data.diamond.data.proposals[format_int(input.proposal, 10)].sessions[format_int(input.visit, 10)]

# Returns the session ID if the subject has write permissions for the
# specific beamline, visit and proposal requested in the input.
user_session := to_number(_session) if {
	session.write_to_beamline_visit
	_session
}

user_session := to_number(_session) if {
	input.proposal in token.claims.subject.proposals
}

user_session := to_number(_session) if {
	_session in token.claims.subject.sessions
}

user_session := to_number(_session) if {
	input.beamline in beamlines
	input.beamline == session.beamline_for(input.proposal, input.visit)
	_session in data.diamond.data.beamlines[input.beamline].sessions
}

default fedid := ""

fedid := token.claims.fedid if token.claims.fedid

# Validates if the subject has permission to modify
# the specific session in the input.
default modify_session := false

modify_session if session.access_session(
	fedid,
	data.diamond.data.sessions[input.session].proposal_number,
	data.diamond.data.sessions[input.session].visit_number,
)

modify_session if {
	data.diamond.data.sessions[input.session].proposal_number in token.claims.subject.proposals
}

modify_session if {
	to_number(input.session) in token.claims.subject.sessions
}

modify_session if {
	session.beamline_for(
		data.diamond.data.sessions[input.session].proposal_number,
		data.diamond.data.sessions[input.session].visit_number,
	) in beamlines
}

subject := data.diamond.data.subjects[fedid] if fedid

else := token.claims.subject if token.claims.subject

# Identifies all beamlines the subject is authorized to access
# based on their assigned permissions.
beamlines contains beamline if {
	not admin.is_admin(fedid)
	some p in subject.permissions
	some beamline in object.get(data.diamond.data.admin, p, [])
}

# Aggregates all session IDs the subject is authorized to view.
# Admins receive a wildcard "*" granting access to all sessions.

# Regular users gain session access through three pathways:
# 1. Direct session membership
# 2. Access via beamline-level permissions
# 3. Access via proposal-level permissions
user_sessions contains "*" if {
	admin.is_admin(fedid)
}

user_sessions contains to_number(session) if {
	not admin.is_admin(fedid)
	some session in subject.sessions
}

user_sessions contains to_number(session) if {
	not admin.is_admin(fedid)
	some beamline in beamlines
	some session in data.diamond.data.beamlines[beamline].sessions
}

user_sessions contains to_number(session) if {
	not admin.is_admin(fedid)
	some p in subject.proposals
	some i in data.diamond.data.proposals[format_int(p, 10)]
	some session in i
}
