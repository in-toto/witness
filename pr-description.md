## Summary

This PR enhances the witness documentation system to provide better developer experience:

- 📚 **Package Documentation**: Added documentation generation for core go-witness packages (cryptoutil, policy, signer, dsse, archivista)
- 🔍 **Enhanced Attestor Docs**: Improved attestor documentation with summaries, usage examples, and realistic command examples
- 🖥️ **CLI Integration**: New `witness attestors docs` command to view attestor documentation directly from CLI
- 🛠️ **Docgen Updates**: Extended docgen tool to handle both attestors and packages
- 📝 **Realistic Examples**: All examples now use proper witness command syntax with required flags

## Changes

### New Features
- Added `cmd/attestor_docs.go` - New CLI command for attestor documentation
- Added `docs/packages/` directory with documentation for core packages
- Enhanced docgen to generate package documentation alongside attestor docs

### Documentation Improvements
- All attestors now have:
  - Summary sections explaining what they do
  - "When to Use" sections with practical scenarios  
  - Realistic examples with proper `witness run` syntax
- Core packages documented with:
  - Package summaries and descriptions
  - Usage scenarios
  - Code examples
  - JSON schemas

### CLI Enhancements
- `witness attestors docs [attestor]` - View documentation for specific attestor
- `witness attestors docs` - List all attestors with summaries
- `witness run --help-attestor <name>` - Quick help for attestor during run

## Related PRs
- Requires companion PR in go-witness repository for the documentation interfaces and content

## Testing
- Run `go run docgen/docs.go` to regenerate documentation
- Try `witness attestors docs git` to see attestor documentation  
- Check generated files in `docs/packages/` and updated `docs/attestors/`

## Future Work
This sets the foundation for further documentation enhancements like:
- Interactive documentation with WASM
- Visual policy builders
- Searchable command database