package diamond.policy.subject_session

import data.diamond.policy.admin
import data.diamond.policy.token
import rego.v1

beamlines contains beamline if {
	some p in data.diamond.data.subjects[token.claims.fedid].permissions
	some beamline in object.get(data.diamond.data.admin, p, [])
}

public_tags := {"public"}

tags contains tag if {
	"super_admin" in data.diamond.data.subjects[token.claims.fedid].permissions
	some tag in object.keys(data.diamond.data.sessions)
}

tags contains formatted_tag if {
	some tag in data.diamond.data.subjects[token.claims.fedid].sessions
	formatted_tag := format_int(tag, 10)
}

tags contains formatted_tag if {
	some beamline in beamlines
	some tag in data.diamond.data.beamlines[beamline].sessions
	formatted_tag := format_int(tag, 10)
}

tags contains tag if {
	some tag in public_tags
}

read_scopes := {
	"read:metadata",
	"read:data",
}

all_scopes := {
	"read:metadata",
	"read:data",
	"write:metadata",
	"write:data",
	"delete:revision",
	"delete:node",
	"create",
	"register",
}

scopes contains scope if {
	"blueapi" in token.claims.aud
	some scope in all_scopes
}

scopes contains scope if {
	some scope in read_scopes
}

exclude_public := tags - public_tags

default allow := false

# Allow to modify and create tiled node if the sessions are accessible to the user

allow if {
	every tag in input.access_blob.tags {
		tag in exclude_public
	}
}
