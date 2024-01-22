package authz

import future.keywords.every
import future.keywords.if
import future.keywords.in

rules["ACCESS-0001"] := {"allow": true, "reason": "Authorized by administrator group membership"} if {
	# Skip this rule if the user is not net
	input.user != null

	# One of the user's groups is "administrators"
	some group in input.user.groups
	group in {"administrators"}
}

rules["ACCESS-0002"] := {"allow": true, "reason": "Authorized by resource ownership"} if {
	# Skip this rule if the resource is not set
	input.resource != null

	# The user is the owner of the resource
	input.user.subject == input.resource.owner
}

rules["ACCESS-0003"] := {"allow": false, "reason": "Access disabled during code freeze"} if {
	# Skip this rule if the context is not set
	input.context != null

	# Access is disabled during code freeze
	input.context.code_freeze == true
}

# Deny all accesses by default
default result := {"allow": false, "reason": "Not authorized"}

# Allow access if any of the rules allow it
result := {"allow": true} if {
	# At least there is one rule match
	some rule in rules

	# All rule matches allow access
	every rule in rules { rule.allow == true }
} else := {"allow": false, "reason": rule.reason} if {
	# At least there is one rule match
	some rule in rules

	# At least one rule match denies access
	not rule.allow
}
