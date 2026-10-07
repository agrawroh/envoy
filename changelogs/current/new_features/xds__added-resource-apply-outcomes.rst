Added a new callback, ``onResourcesApplied``, reporting whether each resource of a CDS or LDS
update was applied, skipped, removed or rejected, so that a tracker can tell a management server
what became of the resources it sent.
