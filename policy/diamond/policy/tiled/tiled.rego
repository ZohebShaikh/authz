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

default scopes := set()

scopes := scopes_for(token.claims)

user_session := to_number(value) if {
	session.write_to_beamline_visit
	value := data.diamond.data.proposals[format_int(input.proposal, 10)].sessions[format_int(input.visit, 10)]
}

_session := data.diamond.data.sessions[format_int(input.session, 10)]

default modify_session := false

modify_session := session.access_session(
	token.claims.fedid,
	_session.proposal_number,
	_session.visit_number,
)

subject := data.diamond.data.subjects[token.claims.fedid]

beamlines contains beamline if {
	not admin.is_admin(token.claims.fedid)
	some p in subject.permissions
	some beamline in object.get(data.diamond.data.admin, p, [])
}

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
