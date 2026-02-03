package diamond.policy.tiled

import data.diamond.policy.admin
import data.diamond.policy.session
import data.diamond.policy.token
import rego.v1

read_scopes := {
	"read:metadata",
	"read:data",
}

write_scopes := {
	"write:metadata",
	"write:data",
	"create:node",
	"register",
}

scopes_for(claims) := read_scopes | write_scopes if {
	"azp" in object.keys(claims)
	endswith(claims.azp, "-blueapi")
}

scopes_for(claims) := read_scopes if {
	"azp" in object.keys(claims)
	not endswith(claims.azp, "-blueapi")
}

scopes_for(claims) := read_scopes if {
	not "azp" in object.keys(claims)
}

# Assign read & write scopes to blueapi clients
# defaults to read-only scopes
default scopes := set()

scopes := scopes_for(token.claims)

# Returns the session ID if the subject has write permissions for the
# specific beamline, visit and proposal requested in the input.
user_session := to_number(value) if {
	session.write_to_beamline_visit
	value := data.diamond.data.proposals[format_int(input.proposal, 10)].sessions[format_int(input.visit, 10)]
}

# Validates if the subject has permission to modify
# the specific session in the input.
default modify_session := false

modify_session := session.access_session(
	token.claims.fedid,
	data.diamond.data.sessions[input.session].proposal_number,
	data.diamond.data.sessions[input.session].visit_number,
)

subject := data.diamond.data.subjects[token.claims.fedid]

# Identifies all beamlines the subject is authorized to access
# based on their assigned permissions.
beamlines contains beamline if {
	not admin.is_admin(token.claims.fedid)
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
	admin.is_admin(token.claims.fedid)
}

user_sessions contains to_number(session) if {
	not admin.is_admin(token.claims.fedid)
	some session in subject.sessions
}

user_sessions contains to_number(session) if {
	not admin.is_admin(token.claims.fedid)
	some beamline in beamlines
	some session in data.diamond.data.beamlines[beamline].sessions
}

user_sessions contains to_number(session) if {
	not admin.is_admin(token.claims.fedid)
	some p in subject.proposals
	some i in data.diamond.data.proposals[format_int(p, 10)]
	some session in i
}
