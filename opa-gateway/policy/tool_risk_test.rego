package toolrisk_test

import rego.v1
import data.toolrisk

request := {"tool": "search_documents", "classification": "internal", "destination": "", "roles": []}

test_search_allowed if {
    toolrisk.decision.allow with input as request
}
test_unknown_denied if {
    d := toolrisk.decision with input as object.union(request, {"tool": "shell"})
    not d.allow
    "unknown tool" in d.reasons
}
test_delete_denied if {
    d := toolrisk.decision with input as object.union(request, {"tool": "delete_documents"})
    not d.allow
}
test_restricted_export_denied_even_for_reviewer if {
    d := toolrisk.decision with input as object.union(request, {"tool": "export_documents", "classification": "restricted", "roles": ["reviewer"]})
    not d.allow
}
test_export_requires_reviewer if {
    not toolrisk.decision.allow with input as object.union(request, {"tool": "export_documents"})
    toolrisk.decision.allow with input as object.union(request, {"tool": "export_documents", "roles": ["reviewer"]})
}
test_external_requires_exact_trusted_destination if {
    not toolrisk.decision.allow with input as object.union(request, {"tool": "send_external", "destination": "evil.partner.example.com"})
    toolrisk.decision.allow with input as object.union(request, {"tool": "send_external", "destination": "partner.example.com"})
}
test_restricted_external_denied if {
    not toolrisk.decision.allow with input as object.union(request, {"tool": "send_external", "classification": "restricted", "destination": "partner.example.com"})
}
test_invalid_classification_denied if {
    not toolrisk.decision.allow with input as object.union(request, {"classification": "secret"})
}
