# HexiGrid interoperability

HexiKeys remains a standalone Windows vault. Its optional HexiGrid bridge uses authenticated local named pipes while the vault is unlocked. It does not bulk-copy the vault into HexiGrid.

## Owner-controlled access

- Pairing is explicit. Pairing material is protected locally and the vault retains its encrypted pairing record.
- Grants target an individual field, destination and constrained operation, with expiry and use limits. References are opaque; editing a field's value invalidates its previous reference.
- Locking, closing or revoking access stops further use. Already-dispatched external effects cannot be undone.
- Agents must receive opaque references and redacted outcomes, not raw credentials. Integration clients must keep secret handling inside their trusted local connector boundary.
- The bridge is optional and requires a compatible HexiGrid build. There is no remote or cloud vault service.

## Verification and limitations

The tests cover authentication, replay, expiry, concurrent use, revocation, locking, callback cancellation and Windows named-pipe behavior using synthetic data. Optional cross-project tests run when `HEXIGRID_ROOT` points to a compatible HexiGrid checkout.

These checks are not an independent security audit. A malicious local process running as the same Windows user, compromised connector, or compromised operating system remains outside the protection this vault can promise. Use the early preview cautiously and report suspected vulnerabilities privately as described in SECURITY.md.
