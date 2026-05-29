# ddd_role.rego
#
# Package: nft_exporter.schemas.ddd_role
#
# Intent: Enforce the CUE file convention from SPEC-AS-SOURCE-CONVENTIONS:
#   Every CUE component file under docs/arch/schemas/ MUST begin with a comment line
#   of the form:
#
#     // DDD role: <Role>
#
#   where <Role> is exactly one of:
#     AggregateRoot | Entity | ValueObject | DomainService | ReadModel | Policy
#
#   Files that lack this header are rejected because:
#     - The DDD role is machine-readable metadata used by downstream tooling (spec validate,
#       ADR generation, architecture diagram extraction).
#     - Missing roles silently break the spec-as-source-of-truth invariant that every schema
#       artefact is typed and owned by a DDD tactical concept.
#
#   NOTE: This is a conceptual/documentation-level Rego rule. The actual CUE file content
#   is not parsed by conftest at runtime (conftest does not load .cue files as input by
#   default). This rule operates on a structured manifest of CUE files provided as input,
#   where each entry carries the file path and the first non-empty line of the file.
#   A companion script (scripts/check-cue-headers.sh or a Makefile target) should build
#   this manifest and feed it to conftest.
#
# Input shape:
#   {
#     "cue_files": [
#       {"path": "docs/arch/schemas/link.cue", "first_line": "// DDD role: AggregateRoot"},
#       ...
#     ]
#   }
#
# Usage: conftest test --policy docs/arch/policies/ <manifest.json>

package nft_exporter.schemas.ddd_role

import future.keywords.contains
import future.keywords.if

# The complete set of valid DDD tactical roles for this project.
valid_roles := {
	"AggregateRoot",
	"Entity",
	"ValueObject",
	"DomainService",
	"ReadModel",
	"Policy",
}

# Build the set of valid header strings for O(1) lookup.
valid_headers[header] if {
	role := valid_roles[_]
	header := sprintf("// DDD role: %s", [role])
}

# Deny any CUE file whose first line is not a valid DDD role header.
deny contains msg if {
	cue_file := input.cue_files[_]
	not valid_headers[cue_file.first_line]
	msg := sprintf(
		"CUE file %q is missing a valid DDD role header; first line is %q; expected one of: %s",
		[
			cue_file.path,
			cue_file.first_line,
			"// DDD role: AggregateRoot|Entity|ValueObject|DomainService|ReadModel|Policy",
		],
	)
}
