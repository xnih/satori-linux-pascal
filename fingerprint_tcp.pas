unit Fingerprint_TCP;

interface

uses
  Classes, dom, XMLRead, sysutils, strutils;

type
  TCPOSGuess = packed record
    OS:string;
    totalweight:integer;
  end;
  PTCPOSGuess = ^TCPOSGuess;

var
  TCPDB:TXMLDocument;
  EttercapDB, p0fsDB, p0fsaDB:TStringList;

function FindTCPOS(flags, signature:string) : string;
function FindEttercapOS(signature:string) : string;
function Findp0fsOS(signature:string) : string;
function Findp0fsaOS(signature:string) : string;
//function FindTCPOS5(signature:string) : string; }
function CompareNames(Item1, Item2: Pointer): Integer;
function LoadTCP:boolean;
function LoadEtterCap:boolean;
function Loadp0fs:boolean;
function Loadp0fsa:boolean;

implementation

function LoadTCP:boolean;
begin
result:=false;
  try
    ReadXMLFile(TCPDB, 'tcp.xml');
    result:=true;
  except
    on E: exception do writeln(e.message);
  end;
end;

function LoadEtterCap:boolean;
var
  temp:tstringlist;
  i, p:integer;

begin
  result:=false;
  temp:=TStringList.Create;
  EttercapDB:=TStringList.Create;
  
  try
    temp.LoadFromFile('etter.finger.os');
    for i:=0 to temp.Count - 1 do
      begin
        p:=pos('#', temp.Strings[i]);
        if p <> 1 then
          if temp.Strings[i] <> '' then
            EttercapDB.Add(temp.Strings[i]);
      end;
    if EttercapDB.Count > 0 then
      result:=true;
  except
    ;
  end;
end;

function Loadp0fs:boolean;
var
  temp:tstringlist;
  i, p:integer;

begin
  result:=false;
  temp:=TStringList.Create;
  p0fsDB:=TStringList.Create;

  try
    temp.LoadFromFile('p0f.fp');
    for i:=0 to temp.Count - 1 do
      begin
        p:=pos('#', temp.Strings[i]);
        if p <> 1 then
          if temp.Strings[i] <> '' then
            p0fsDB.Add(temp.Strings[i]);
      end;
    if p0fsDB.Count > 0 then
      result:=true;
  except
    ;
  end;
end;

function Loadp0fsa:boolean;
var
  temp:tstringlist;
  i, p:integer;

begin
  result:=false;
  temp:=TStringList.Create;
  p0fsaDB:=TStringList.Create;

  try
    temp.LoadFromFile('p0fa.fp');
    for i:=0 to temp.Count - 1 do
      begin
        p:=pos('#', temp.Strings[i]);
        if p <> 1 then
          if temp.Strings[i] <> '' then
            p0fsaDB.Add(temp.Strings[i]);
      end;
    if p0fsaDB.Count > 0 then
      result:=true;
  except
    ;
  end;
end;

function CompareNames(Item1, Item2: Pointer): Integer;
begin
  Result := TCPOSGuess(Item2^).totalweight - TCPOSGuess(Item1^).totalweight
end;

function FindTCPOS (flags, signature:string) : string;
var
  OSGuess:PTCPOSGuess;
  found:boolean;
  MyList:TList;
  x, y, z, p:integer;
  os, s, s1, s2, s3, s4:string;
  FingerPrintsNodeList, TestsNodeList:TDomNodeList;

begin
  MyList:=TList.Create;
  
  try
    if Assigned(TCPDB) then
      begin
        FingerprintsNodeList:=TCPDB.DocumentElement.FindNode('fingerprints').ChildNodes;
      end;
  except
    on E: exception do writeln(e.message);
  end;

  for x:= 0 to FingerPrintsNodeList.Count - 1 do
    begin
      TestsNodeList:=FingerprintsNodeList.Item[x].FindNode('tcp_tests').ChildNodes;
      for y:= 0 to TestsNodeList.Count - 1 do
        begin
          if lowercase(TestsNodeList.Item[y].Attributes.GetNamedItem('matchtype').NodeValue) = 'exact' then
            begin
              try
                if TestsNodeList.Item[y].Attributes.GetNamedItem('tcpsig').NodeValue = signature then
                  if TestsNodeList.Item[y].Attributes.GetNamedItem('tcpflag').NodeValue = flags then
                  begin
                    //Try to find if OS already in OSGuess
                    found:=false;
                    z:=0;
                    while (z < MyList.Count) and (found = false) do
                      begin
                        OSGuess:=MyList[z];
                        if OSGuess^.OS = FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue then
                          found:=true
                        else
                          inc(z);
                      end;

                    if z < MyList.Count then
                      begin
                        OSGuess:=MyList[z];
                        OSGuess^.totalweight := OSGuess^.totalweight + StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                        MyList[z]:=OSGuess;
                      end
                    else
                      begin
                        New(OSGuess);

                        //Initialize Info
                        OSGuess^.totalweight:=0;

                        OSGuess^.OS          := FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue;
                        OSGuess^.totalweight := StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                        MyList.Add(OSGuess);
                      end;
                  end;
              except
                ;
              end;
            end
          else
            begin
              try
                s:=TestsNodeList.Item[y].Attributes.GetNamedItem('tcpsig').NodeValue;
                p:=pos('*', s);
                s1:=copy(s, 1, p-1);
                s2:=copy(s, p+1, length(s) - p);
                s3:=copy(signature, 1, p-1);
                s4:=copy(signature, p+1, length(signature) - p);
                if s4 <> '' then
                  while s4[1] <> ':' do
                    begin
                      s4:=copy(s4, 2, length(s4) - 1);
                      if s4 = '' then break;
                    end;
                if (s1 = s3) and (s2 = s4) and (TestsNodeList.Item[y].Attributes.GetNamedItem('tcpflag').NodeValue = flags) then
                  begin
                    //Try to find if OS already in OSGuess
                    found:=false;
                    z:=0;
                    while (z < MyList.Count) and (found = false) do
                      begin
                        OSGuess:=MyList[z];
                        if OSGuess^.OS = FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue then
                          found:=true
                        else
                          inc(z);
                      end;

                    if z < MyList.Count then
                      begin
                        OSGuess:=MyList[z];
                        OSGuess^.totalweight := OSGuess^.totalweight + StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                        MyList[z]:=OSGuess;
                      end
                    else
                      begin
                        New(OSGuess);

                        //Initialize Info
                        OSGuess^.totalweight:=0;

                        OSGuess^.OS          := FingerprintsNodeList.Item[x].Attributes.GetNamedItem('name').NodeValue;
                        OSGuess^.totalweight := StrToInt(TestsNodeList.Item[y].Attributes.GetNamedItem('weight').NodeValue);
                        MyList.Add(OSGuess);
                      end;
                  end;
              except
                ;
              end;
            end;
        end;
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

function FindEttercapOS(signature:string) : string;
//ettercap
var
  OSGuess:PTCPOSGuess;
  MyList:TList;
  x, p:integer;
  os, s:string;

begin
  MyList:=TList.Create;

  if Assigned(EttercapDB) then
  for x:= 0 to EttercapDB.Count - 1 do
    begin
      s:=EttercapDB.Strings[x];

      p:=pos(signature, s);
      if p > 0 then
        begin
          s:=ReverseString(s);
          p:=pos(':', s);
          os:=ReverseString(copy(s, 1, p-1));

          New(OSGuess);

          //Initialize Info
          OSGuess^.totalweight:=5;

          OSGuess^.OS          := Os;
          MyList.Add(OSGuess);
        end;
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

function Findp0fsOS(signature:string) : string;
//p0f Syn
var
  OSGuess:PTCPOSGuess;
  MyList:TList;
  x, p:integer;
  os, s, s1, s2, s3, s4, tempsig:string;
  found:boolean;

begin
  MyList:=TList.Create;

  if Assigned(p0fsDB) then
  for x:= 0 to p0fsDB.Count - 1 do
    begin
      tempsig:=signature;
      s:=p0fsDB.Strings[x];

      p:=pos(tempsig, s);
      if p > 0 then
        begin
          s:=ReverseString(s);
          p:=pos(':', s);
          os:=ReverseString(copy(s, 1, p-1));
          s:=copy(s, p + 1, length(s) - p);
          p:=pos(':', s);
          os:=ReverseString(copy(s, 1, p-1)) + ' ' + os;

          New(OSGuess);

          //Initialize Info
          OSGuess^.totalweight:=5;

          OSGuess^.OS          := Os;
          MyList.Add(OSGuess);
        end
      else
        begin
          found:=false;
          p:=pos('M*', s);
          if p > 0 then
            begin
              found:=true;
              p:=pos('M', tempsig);
              s1:=copy(tempsig, 1, p-1);
              s2:=copy(tempsig, p + 1, length(tempsig)-p);
              p:=pos(',', s2);
              if p > 0 then
                begin
                  s2:=copy(s2, p + 1, length(s2) - p);
                  tempsig:=s1 + 'M*,' + s2;
                end
              else
                begin
                  p:=pos(':', s2);
                  s2:=copy(s2, p + 1, length(s2) - p);
                  tempsig:=s1 + 'M*:' + s2;
                end;
            end;

          p:=pos('%', s);
          if p = 1 then
            begin
              found:=true;
              p:=pos(':', s);
              s3:=copy(s, 2, p-2);

              p:=pos(':', tempsig);
              s1:=copy(tempsig, 1, p-1);
              s2:=copy(tempsig, p + 1, length(tempsig)-p);

              try
                p:=StrToInt(s1) mod StrToInt(s3);
                if p = 0 then
                  tempsig:='%' + s3 + ':' + s2;
              except
                ;
              end;
            end;

          p:=pos('W%', s);
          if p > 0 then
            begin
              found:=true;
              s3:=copy(s, p+2, length(s) - p - 1);
              p:=pos(',', s3);
              s3:=copy(s3, 1, p-1);

              p:=pos('W', tempsig);
              if p > 0 then
                begin
                  s1:=copy(tempsig, 1, p-1);
                  s2:=copy(tempsig, p + 1, length(tempsig)-p);
                  p:=pos(',', s2);
                  s4:=copy(s2, 1, p-1);
                  s2:=copy(s2, p+1, length(s2) - p);

                  try
                    if s4 <> '0' then
                      begin
                        p:=StrToInt(s4) mod StrToInt(s3);
                        if p = 0 then
                          s:=s1 + 'W%' + s3 + ',' + s2;
                      end;
                  except
                    ;
                  end;
                end;
            end;

          if found then
            begin
              p:=pos(tempsig, s);
              if p > 0 then
                begin
                  s:=ReverseString(s);
                  p:=pos(':', s);
                  os:=ReverseString(copy(s, 1, p-1));
                  s:=copy(s, p + 1, length(s) - p);
                  p:=pos(':', s);
                  os:=ReverseString(copy(s, 1, p-1)) + ' ' + os;

                  New(OSGuess);

                  //Initialize Info
                  OSGuess^.totalweight:=5;

                  OSGuess^.OS          := Os;
                  MyList.Add(OSGuess);
                end

            end;
        end;
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

function Findp0fsaOS(signature:string) : string;
//p0f Syn ACK
var
  OSGuess:PTCPOSGuess;
  MyList:TList;
  x, p:integer;
  os, s, s1, s2, tempsig:string;
  found:boolean;

begin
  try
    MyList:=TList.Create;

    if Assigned(p0fsaDB) then
    for x:= 0 to p0fsaDB.Count - 1 do
      begin
        tempsig:=signature;
        s:=p0fsaDB.Strings[x];

        p:=pos(':.', tempsig);     //worthless why here?

        p:=pos(tempsig, s);
        if p > 0 then
          begin
            s:=ReverseString(s);
            p:=pos(':', s);
            os:=ReverseString(copy(s, 1, p-1));
            s:=copy(s, p + 1, length(s) - p);
            p:=pos(':', s);
            os:=ReverseString(copy(s, 1, p-1)) + ' ' + os;

            New(OSGuess);

            //Initialize Info
            OSGuess^.totalweight:=5;

            OSGuess^.OS          := Os;
            MyList.Add(OSGuess);
          end
        else
          begin
            found:=false;
            p:=pos('M*', s);
            if p > 0 then
              begin
                found:=true;
                p:=pos('M', tempsig);
                s1:=copy(tempsig, 1, p-1);
                s2:=copy(tempsig, p + 1, length(tempsig)-p);
                p:=pos(',', s2);
                if p > 0 then
                  begin
                    s2:=copy(s2, p + 1, length(s2) - p);
                    tempsig:=s1 + 'M*,' + s2;
                  end
                else
                  begin
                    p:=pos(':', s2);
                    s2:=copy(s2, p + 1, length(s2) - p);
                    tempsig:=s1 + 'M*:' + s2;
                  end;
              end;

            if found then
              begin
                p:=pos(tempsig, s);
                if p > 0 then
                  begin
                    s:=ReverseString(s);
                    p:=pos(':', s);
                    os:=ReverseString(copy(s, 1, p-1));
                    s:=copy(s, p + 1, length(s) - p);
                    p:=pos(':', s);
                    os:=ReverseString(copy(s, 1, p-1)) + ' ' + os;

                    New(OSGuess);

                    //Initialize Info
                    OSGuess^.totalweight:=5;

                    OSGuess^.OS          := Os;
                    MyList.Add(OSGuess);
                  end

              end;
          end;
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
        for x := 0 to MyList.Count - 1 do   //original idea was to only do 5, may have to change this to 0..4 since as it is currently it is worthless!
          begin
            OSGuess:=MyList[x];
            os:=os + OSGuess^.OS + ' [' + IntToStr(OSGuess^.totalweight) + ']; ';
          end;
      end;

    result := os;

    for x:=0 to MyList.Count - 1 do
      begin
        try
          OSGuess:=MyList[x];
          Dispose(OSGuess);
        except
          ;
        end;
      end;
  finally
    MyList.Free;
  end;
end;

{function FindTCPOS5(signature:string) : string;
//mtu lookup
var
  OSGuess:PTCPOSGuess;
  MyList:TList;
  x, p:integer;
  os, s, s1, s2:string;
  found:boolean;

begin
  MyList:=TList.Create;

  if Assigned(TCPDB5) then
  for x:= 0 to TCPDB5.Count - 1 do
    begin
      s:=TCPDB5.Strings[x];

      p:=pos(chr(9), s);
      if p > 0 then
        begin
          os:=copy(s, p+1, length(s) - p);
          s:=copy(s, 1, p-1);

          if signature = s then
            begin
              New(OSGuess);

              OSGuess^.OS          := Os;
              MyList.Add(OSGuess);
            end;
        end;
    end;

  MyList.Sort(@CompareNames);

  os:='';

  if MyList.Count < 5 then
    begin
      for x := 0 to MyList.Count - 1 do
        begin
          OSGuess:=MyList[x];
          os:=os + OSGuess.OS;
        end;
    end
  else
    begin
      for x := 0 to MyList.Count - 1 do
        begin
          OSGuess:=MyList[x];
          os:=os + OSGuess.OS;
        end;
    end;

  result := os;

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
end; }

end.

