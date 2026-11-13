package toolrisk

import rego.v1

known_tools := {"search_documents", "export_documents", "delete_documents", "send_external"}
valid_classifications := {"public", "internal", "restricted"}

reasons contains "unknown tool" if {
    not input.tool in known_tools
}
reasons contains "invalid data classification" if {
    not input.classification in valid_classifications
}
reasons contains "destructive operations are blocked" if {
    input.tool == "delete_documents"
}
reasons contains "restricted data cannot be exported" if {
    input.tool == "export_documents"
    input.classification == "restricted"
}
reasons contains "external communication requires a trusted destination" if {
    input.tool == "send_external"
    not input.destination in {"partner.example.com"}
}
reasons contains "restricted data cannot be sent externally" if {
    input.tool == "send_external"
    input.classification == "restricted"
}
reasons contains "export requires the reviewer role" if {
    input.tool == "export_documents"
    not "reviewer" in input.roles
}

decision := {"allow": count(reasons) == 0, "reasons": sort(reasons)}
