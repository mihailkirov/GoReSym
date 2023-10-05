module github.com/mihailkirov/GoReSym

replace github.com/mandiant/GoReSym => ./

go 1.21

require (
	github.com/elliotchance/orderedmap v1.5.0
	golang.org/x/arch v0.5.0
	rsc.io/binaryregexp v0.2.0
)

require github.com/stretchr/testify v1.8.4 // indirect

require golang.org/x/exp v0.0.0-20230905200255-921286631fa9
