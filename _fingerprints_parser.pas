unit _fingerprints_parser;

interface

uses Classes, XMLRead, dom;

// parse the document (time consuming)
// returns :
//            true  - success
//            false - failure
function ReadDatabaseDHCP(fname : string) : boolean;

var
  parsed:boolean; // document state (parsed or not)

  // fingerprints.xml contents
  fdoc             : TXMLDocument;
  mdoc             : TStringList;
  DHCPDB           : TXMLDocument;

implementation

// parse the document (time consuming)
// returns :
//            true  - success
//            false - failure
function ReadDatabaseDHCP(fname : string) : boolean;
begin
  // start parsing
  parsed := true;

  try
    ReadXMLFile(DHCPDB, fname);
  except
    parsed := false;
  end;

  result := parsed;
end;


begin
  parsed := false;
end.

