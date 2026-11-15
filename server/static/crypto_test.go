package static

import (
	exec "os/exec"
	testing "testing"
)

// The browser's crypto has to read and write exactly what the Go client does.
// The script runs docs_crypto.js on the vendored libsodium against
// client/testdata/vectors.json. Without Node there is nothing to run it with.
func TestBrowserCryptoMatchesTheVectors( t *testing.T ) {
	node , err := exec.LookPath( "node" )
	if err != nil { t.Skip( "node is not installed" ) }
	output , err := exec.Command( node , "../../scripts/check_crypto.js" ).CombinedOutput()
	if err != nil { t.Fatalf( "%s" , output ) }
}

// The Documents screen's key handling (docs.js) against a dishonest server:
// what the Go client refuses, it refuses or asks about first.
func TestBrowserKeyHandling( t *testing.T ) {
	node , err := exec.LookPath( "node" )
	if err != nil { t.Skip( "node is not installed" ) }
	output , err := exec.Command( node , "../../scripts/check_docs_keys.js" ).CombinedOutput()
	if err != nil { t.Fatalf( "%s" , output ) }
}
