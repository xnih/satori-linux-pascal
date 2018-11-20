unit Fingerprint_dhcp;

interface

uses
  Classes, dom, XMLRead, sysutils;

type
  DHCPOSGuess = record
    OS:string;
    optionsweight:integer;
    option55weight:integer;
    vendorclassweight:integer;
    totalweight:integer;
    URL:string;
    icon:string;
    OSClass:string;
  end;
  PDHCPOSGuess = ^DHCPOSGuess;

var
  dhcpdb:TXMLDocument;

function FindDHCPOS (options, option55, vendorclass, bootptype:string; ignoretype:boolean; UseAny:boolean) : string;
function CompareNames(Item1, Item2: Pointer): Integer;
function LoadDHCP:boolean;

implementation


function LoadDHCP:boolean;
begin
result:=false;
  try
    ReadXMLFile(DHCPDB, 'dhcp.xml');
    result:=true;
  except
    on E: exception do writeln(e.message);
  end;
end;

function CompareNames(Item1, Item2: Pointer): Integer;
begin
  Result := DHCPOSGuess(Item2^).totalweight - DHCPOSGuess(Item1^).totalweight
end;

function FindDHCPOS (options, option55, vendorclass, bootptype:string; ignoretype:boolean; UseAny:boolean) : string;
var
  OSGuess:PDHCPOSGuess;
  MyList:TList;
  found, foundoption55, foundoptions, foundvendorclass:boolean;
  x, y, z, p:integer;
  os:string;
  RunTest:boolean;
  PassNode, child:TDOMNode;
  FingerPrintsNodeList, TestsNodeList:TDomNodeList;

begin
  MyList:=TList.Create;
  foundoption55:=false;
  foundoptions:=false;
  foundvendorclass:=false;

  try
    if Assigned(DHCPDB) then
      begin
        FingerprintsNodeList:=DHCPDB.DocumentElement.FindNode('fingerprints').ChildNodes;
      end;
  except
    on E: exception do writeln(e.message);
  end;

  for x:= 0 to FingerPrintsNodeList.Count - 1 do
    begin
      TestsNodeList:=FingerprintsNodeList.Item[x].FindNode('dhcp_tests').ChildNodes;
      for y:= 0 to TestsNodeList.Count - 1 do
        begin
          if option55 <> '' then
            try
              RunTest:=false;
              
{              if ignoreType then
                begin
                  if (TestsNodeList.Item[y].Attributes.GetNamedItem('dhcpoption55').NodeValue = Option55) then
                    RunTest:=true;
                end
              else if UseAny then
                begin
                  if (TestsNodeList.Item[y].Attributes.GetNamedItem('dhcpoption55').NodeValue = Option55) and
                    ((lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcptype').NodeValue = lowercase(bootptype)) or
                    (lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcptype').NodeValue = 'any')) then
                    RunTest:=true;
                end
              else //normal }
              
                begin
                  if (TestsNodeList.Item[y].Attributes.GetNamedItem('dhcpoption55').NodeValue = Option55) then
                    if lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcptype').NodeValue) = lowercase(bootptype) then
                      RunTest:=true;
                end;



              if RunTest then
                begin
                  //Try to find if OS already in OSGuess
                  found:=false;
                  z:=0;
                  while (z < MyList.Count) and (found = false) do
                    begin
                      OSGuess:=MyList[z];
                      if OSGuess^.OS = FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue then
                        begin
                          found:=true;
                          foundoption55:=true;
                        end
                      else
                        inc(z);
                    end;

                  if z < MyList.Count then
                    begin
                      foundoption55:=true;
                      OSGuess:=MyList[z];
                      OSGuess^.option55weight := OSGuess^.option55weight + StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                      MyList[z]:=OSGuess;
                    end
                  else
                    begin
                      foundoption55:=true;
                      New(OSGuess);

                      //Initialize Info
                      OSGuess^.optionsweight:=0;
                      OSGuess^.option55weight:=0;
                      OSGuess^.vendorclassweight:=0;
                      OSGuess^.totalweight:=0;
                      OSGuess^.URL:='';
                      OSGuess^.icon:='';
                      OSGuess^.OSClass:='';

                      OSGuess^.OS             := FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue;
                      OSGuess^.option55weight := StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                      MyList.Add(OSGuess);
                    end;
                end;
            except
              ;
            end;

          if options <> '' then
            try
              RunTest:=false;

{              if ignoreType then
                begin
                  if (DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcpoptions = options) then
                    RunTest:=true;
                end
              else if UseAny then
                begin
                  if (DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcpoptions = options) and
                     ((lowercase(DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcptype) = lowercase(bootptype)) or
                     (lowercase(DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcptype) = 'any')) then
                    RunTest:=true;
                end
              else   //normal }
                begin
                  if (TestsNodeList.Item[y].Attributes.GetNamedItem('dhcpoptions').NodeValue = Options) then
                    if lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcptype').NodeValue) = lowercase(bootptype) then
                      RunTest:=true;
                end;

              if RunTest then
                begin
                  //Try to find OS already in OSGuess
                  found:=false;
                  z:=0;
                  while (z < MyList.Count) and (found = false) do
                    begin
                      OSGuess:=MyList[z];
                      if OSGuess^.OS = FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue then
                        begin
                          found:=true;
                          foundoptions:=true;
                        end
                      else
                        inc(z);
                    end;

                  if z < MyList.Count then
                    begin
                      foundoptions:=true;
                      OSGuess:=MyList[z];
                      OSGuess^.optionsweight := OSGuess^.optionsweight + StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                      MyList[z]:=OSGuess;
                    end
                  else
                    begin
                      foundoptions:=true;
                      New(OSGuess);

                      //Initialize Info
                      OSGuess^.optionsweight:=0;
                      OSGuess^.option55weight:=0;
                      OSGuess^.vendorclassweight:=0;
                      OSGuess^.totalweight:=0;
                      OSGuess^.URL:='';
                      OSGuess^.icon:='';
                      OSGuess^.OSClass:='';

                      OSGuess^.OS             := FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue;
                      OSGuess^.optionsweight := StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                      MyList.Add(OSGuess);
                    end;
                end;
            except
              ;
            end;

          if VendorClass <> '' then
            try
              if lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('matchtype').NodeValue) = 'exact' then

                RunTest:=false;

{                if ignoreType then
                  begin
                    if (lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue) = lowercase(VendorClass)) then
                      RunTest:=true;
                  end
                else if UseAny then
                  begin
                    if (TestsNodeList.Item[y].Attributes.GetNamedItem('dhcpvendorcode').NodeValue = lowercase(VendorClass)) and
                       ((lowercase(DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcptype) = lowercase(bootptype)) or
                       (lowercase(DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcptype) = 'any')) then
                      RunTest:=true;
                  end
                else    //normal }
                  begin
                    if (lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcpvendorcode').NodeValue) = lowercase(VendorClass)) then
                      if (lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcptype').NodeValue) = lowercase(bootptype)) then
                      RunTest:=true;
                  end;

                if RunTest then
                  begin
                    //try to find OS already in OSGuesses
                    found:=false;
                    z:=0;
                    while (z < MyList.Count) and (found = false) do
                      begin
                        OSGuess:=MyList[z];
                        if OSGuess^.OS = FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue then
                          begin
                            found:=true;
                            foundvendorclass:=true;
                          end
                        else
                          inc(z);
                      end;

                    if z < MyList.Count then
                      begin
                        foundvendorclass:=true;
                        OSGuess:=MyList[z];
                        OSGuess^.vendorclassweight := OSGuess^.vendorclassweight + StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                        MyList[z]:=OSGuess;
                      end
                    else
                      begin
                        foundvendorclass:=true;
                        New(OSGuess);

                        //Initialize Info
                        OSGuess^.optionsweight:=0;
                        OSGuess^.option55weight:=0;
                        OSGuess^.vendorclassweight:=0;
                        OSGuess^.totalweight:=0;
                        OSGuess^.URL:='';
                        OSGuess^.icon:='';
                        OSGuess^.OSClass:='';

                        OSGuess^.OS                := FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue;
                        OSGuess^.vendorclassweight := StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);

                        MyList.Add(OSGuess);
                      end;
                    end;

              if lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('matchtype').NodeValue) = 'partial' then
                begin
                  p:=pos(lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcpvendorcode').NodeValue), lowercase(VendorClass));
                  RunTest:=false;

{                  if ignoreType then
                    begin
                      if (p > 0) then
                        RunTest:=true;
                    end
                  else if UseAny then
                    begin
                      if (DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcpvendorcode = lowercase(vendorClass)) and
                         ((lowercase(DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcptype) = lowercase(bootptype)) or
                         (lowercase(DHCPDB.Fingerprints.Fingerprint[x].Dhcp_tests.Test[y].Dhcptype) = 'any')) then
                        RunTest:=true;
                    end
                  else //Normal }
                    begin
                      if (p > 0) and (lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('dhcptype').NodeValue) = lowercase(bootptype)) then
                        RunTest:=true;
                    end;

                  if RunTest then
                    begin
                      //try to find OS already in OSGuesses
                      found:=false;
                      z:=0;
                      while (z < MyList.Count) and (found = false) do
                        begin
                          OSGuess:=MyList[z];
                          if OSGuess^.OS = FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue then
                            begin
                              found:=true;
                              foundvendorclass:=true;
                            end
                          else
                            inc(z);
                        end;

                      if z < MyList.Count then
                        begin
                          foundvendorclass:=true;
                          OSGuess:=MyList[z];
                          OSGuess^.vendorclassweight := OSGuess^.vendorclassweight + StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                          MyList[z]:=OSGuess;
                        end
                      else
                        begin
                          foundvendorclass:=true;
                          New(OSGuess);

                          //Initialize Info
                          OSGuess^.optionsweight:=0;
                          OSGuess^.option55weight:=0;
                          OSGuess^.vendorclassweight:=0;
                          OSGuess^.totalweight:=0;
                          OSGuess^.URL:='';
                          OSGuess^.icon:='';
                          OSGuess^.OSClass:='';

                          OSGuess^.OS                := FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue;
                          OSGuess^.vendorclassweight := StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);

                          MyList.Add(OSGuess);
                        end;
                    end;
                end;
            except
              ;
            end;
        end;
    end;

  for x := 0 to MyList.Count - 1 do
    begin
      OSGuess:=MyList[x];
      OSGuess^.totalweight:=OSGuess^.optionsweight + OSGuess^.option55weight + OSGuess^.vendorclassweight;
      MyList[x]:=OSGuess;
    end;

  MyList.Sort(@CompareNames);

  os:='';

  if MyList.Count < 5 then
    begin
      for x := 0 to MyList.Count - 1 do
        begin
          OSGuess:=MyList[x];
          os:=os + OSGuess^.OS + ' [' + IntToStr(OSGuess^.totalweight) + ']; ';
        end;
    end
  else
    begin
      for x := 0 to MyList.Count - 1 do
        begin
          OSGuess:=MyList[x];
          os:=os + OSGuess^.OS + ' [' + IntToStr(OSGuess^.totalweight) + ']; ';
        end;
    end;

  result := os;
  if (foundoption55 = false) and (option55 <> '') then
    option55:=chr(9) + option55;
  if (foundoptions = false) and (options <> '') then
    options:=chr(9) + options;
  if (foundvendorclass = false) and (vendorclass <> '') then
    vendorclass:=chr(9) + vendorclass;

  for x:=0 to MyList.Count - 1 do
    begin
      try
        OSGuess:=MyList[x];
        Dispose(OSGuess);
      except
        ;
      end;
    end;

  MyList.Free;
end;

end.

