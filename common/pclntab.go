package common

import (
	"fmt"

	"github.com/mandiant/GoReSym/objfile"
)

type pcLnTabMetadata struct {
	VA            uint64
	Version       string
	Endianess     string
	CpuQuantum    uint32
	CpuQuantumStr string
	PointerSize   uint32
}

type funcMetadata struct {
	Start       uint64
	End         uint64
	PackageName string
	FullName    string
}

type extractMetadata struct {
	Version string
	TabMeta pcLnTabMetadata
	Func    funcMetadata
}

func getFuncMetadataViaPclntab(fileName string, symbolName string) (*funcMetadata, error) {
	metadata := extractMetadata{}
	file, err := objfile.Open(fileName)
	if err != nil {
		return nil, fmt.Errorf("invalid file: %w", err)
	}

	var knownPclntabVA = uint64(0)
	var knownGoTextBase = uint64(0)
restartParseWithRealTextBase:
	tabs, err := file.PCLineTable("", knownPclntabVA, knownGoTextBase)
	if err != nil {
		return nil, fmt.Errorf("failed to read pclntab: %w", err)
	}

	if len(tabs) == 0 {
		return nil, fmt.Errorf("no pclntab candidates found")
	}

	var moduleData *objfile.ModuleData = nil
	var finalTab *objfile.PclntabCandidate = &tabs[0]
	for _, tab := range tabs {
		metadata.TabMeta.VA = tab.PclntabVA
		metadata.TabMeta.Version = tab.ParsedPclntab.Go12line.Version.String()
		metadata.TabMeta.Endianess = tab.ParsedPclntab.Go12line.Binary.String()
		metadata.TabMeta.PointerSize = tab.ParsedPclntab.Go12line.Ptrsize

		// this can be a little tricky to locate and parse properly across all go versions
		// since moduledata holds a pointer to the pclntab, we can (hopefully) find the right candidate by using it to find the moduledata.
		// if that location works, then we must have given it the correct pclntab VA. At least in theory...
		// The resolved offsets within the pclntab might have used the wrong base though! We'll fix that later.
		_, tmpModData, err := file.ModuleDataTable(tab.PclntabVA, metadata.Version, metadata.TabMeta.Version, metadata.TabMeta.PointerSize == 8, metadata.TabMeta.Endianess == "LittleEndian")
		if err == nil && tmpModData != nil {
			// if the search candidate relied on a moduledata va, make sure it lines up with ours now
			stomppedMagicMetaConstraintsValid := true
			if tab.StompMagicCandidateMeta != nil {
				stomppedMagicMetaConstraintsValid = tab.StompMagicCandidateMeta.SuspectedModuleDataVa == tmpModData.VA
			}

			if knownGoTextBase == 0 && knownPclntabVA == 0 && stomppedMagicMetaConstraintsValid {
				// assign real base and restart pclntab parsing with correct VAs!
				knownGoTextBase = tmpModData.TextVA
				knownPclntabVA = tab.PclntabVA
				goto restartParseWithRealTextBase
			}

			// we already have pclntab candidates with the right VA, but which candidate?? The one that finds a valid moduledata!
			finalTab = &tab
			moduleData = tmpModData
			break
		}
	}

	// to be sure we got the right pclntab we had to have found a moduledat as well. If we didn't, then we failed to find the pclntab (correctly) as well
	if moduleData == nil {
		return nil, fmt.Errorf("no valid pclntab or moduledata found")
	}

	for _, elem := range finalTab.ParsedPclntab.Funcs {
		if !(elem.Name == symbolName) {
			continue
		}
		metadata.Func = funcMetadata{
			Start:       elem.Entry,
			End:         elem.End,
			PackageName: elem.PackageName(),
			FullName:    elem.Name,
		}
	}
	if metadata.Func.Start == 0 {
		return nil, fmt.Errorf("not found symbol %q", symbolName)
	}

	return &metadata.Func, nil
}
