# MiniMCRIT

This helper package internalizes central DTOs and the McritClient itself into this plugin, in order to remove excessive package dependencies.  
Package and class structure is identical to MCRIT itself.  
Changes include swapping the Levenshtein implementation to a pure Python variant and removing the MinHash dependencies (which incur numpy and more).  
MiniMCRIT will need to be updated whenever DTOs in core MCRIT are changed, which, however, is not expected to occur regularly.