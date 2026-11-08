// Package all registers every analyzer and scanner. Import it for its side
// effect wherever code is analyzed, so the CLI and the hosted ratings in
// package score use the same set.
package all

import (
	_ "github.com/roburns/urfluency-cli/analyzers/c"
	_ "github.com/roburns/urfluency-cli/analyzers/cpp"
	_ "github.com/roburns/urfluency-cli/analyzers/csharp"
	_ "github.com/roburns/urfluency-cli/analyzers/dart"
	_ "github.com/roburns/urfluency-cli/analyzers/golang"
	_ "github.com/roburns/urfluency-cli/analyzers/java"
	_ "github.com/roburns/urfluency-cli/analyzers/javascript"
	_ "github.com/roburns/urfluency-cli/analyzers/kotlin"
	_ "github.com/roburns/urfluency-cli/analyzers/php"
	_ "github.com/roburns/urfluency-cli/analyzers/powershell"
	_ "github.com/roburns/urfluency-cli/analyzers/python"
	_ "github.com/roburns/urfluency-cli/analyzers/ruby"
	_ "github.com/roburns/urfluency-cli/analyzers/rust"
	_ "github.com/roburns/urfluency-cli/analyzers/secrets"
	_ "github.com/roburns/urfluency-cli/analyzers/shell"
	_ "github.com/roburns/urfluency-cli/analyzers/swift"
)
