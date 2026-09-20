# Bootstrap preflight fixture

This directory contains public signed material for the isolated
`tden-bond-20260920-r5` test network. It contains no private keys or user wallets.
It is used only by CI to execute the actual archived bootstrap verifier with the
archive's original metadata, configuration profile and trust template. It is not
included in the node installation package and is not a deployment seed source.

The verifier checks signature thresholds and expiry normally. Renew this fixture
through the offline testnet signing procedure before its manifest expires; do
not disable time, root, digest or signature checks to make a build pass.

This preflight does not replace full installation and upgrade acceptance.
