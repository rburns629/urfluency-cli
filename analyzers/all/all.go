// Package all registers every analyzer and scanner. Import it for its side
// effect wherever code is analyzed, so the CLI and the hosted ratings in
// package score use the same set.
package all

import (
	_ "github.com/rburns629/urfluency-cli/analyzers/c"
	_ "github.com/rburns629/urfluency-cli/analyzers/cpp"
	_ "github.com/rburns629/urfluency-cli/analyzers/csharp"
	_ "github.com/rburns629/urfluency-cli/analyzers/dart"
	_ "github.com/rburns629/urfluency-cli/analyzers/golang"
	_ "github.com/rburns629/urfluency-cli/analyzers/java"
	_ "github.com/rburns629/urfluency-cli/analyzers/javascript"
	_ "github.com/rburns629/urfluency-cli/analyzers/kotlin"
	_ "github.com/rburns629/urfluency-cli/analyzers/php"
	_ "github.com/rburns629/urfluency-cli/analyzers/powershell"
	_ "github.com/rburns629/urfluency-cli/analyzers/python"
	_ "github.com/rburns629/urfluency-cli/analyzers/ruby"
	_ "github.com/rburns629/urfluency-cli/analyzers/rust"
	_ "github.com/rburns629/urfluency-cli/analyzers/secrets"
	_ "github.com/rburns629/urfluency-cli/analyzers/shell"
	_ "github.com/rburns629/urfluency-cli/analyzers/swift"
)
