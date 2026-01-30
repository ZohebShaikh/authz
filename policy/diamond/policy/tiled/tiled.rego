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

user_session := to_number(key) if {
	session.write_to_beamline_visit
	some key, value in data.diamond.data.sessions
	value.beamline == input.beamline
	value.proposal_number == input.proposal
	value.visit_number == input.visit
}

_session := data.diamond.data.sessions[format_int(input.session, 10)]

default modify_session := false

modify_session := session.access_session(
	token.claims.fedid,
	_session.proposal_number,
	_session.visit_number,
)

user_sessions contains "*" if {
	admin.is_admin(token.claims.fedid)
}

user_sessions contains to_number(key) if {
	not admin.is_admin(token.claims.fedid)
	some key, value in data.diamond.data.sessions
	session.access_session(token.claims.fedid, value.proposal_number, value.visit_number)
}
