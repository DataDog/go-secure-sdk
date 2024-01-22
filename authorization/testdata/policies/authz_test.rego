package authz

import future.keywords.if

test_default_access if {
	result = {"allow": false, "reason": "Not authorized"} with input as {}
}

test_administrator_access_ok if {
	result = {"allow": true} with input as {"user": {"subject": "user:123", "groups": ["administrators"]}}
}

test_resource_owner_access_ok if {
	result = {"allow": true} with input as {"user": {"subject": "user:123", "groups": ["group:456"]}, "resource": {"owner": "user:123"}}
}

test_deny_during_code_freeze_access_ok if {
	result = {"allow": false, "reason": "Access disabled during code freeze"} with input as {"user": {"subject": "user:123", "groups": ["administrators"]}, "context": {"code_freeze": true}}
}
