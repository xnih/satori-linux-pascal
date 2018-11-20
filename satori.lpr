program satori;

{$mode objfpc}{$H+}

uses
  {$IFDEF UNIX}
  cthreads,
  cmem,
  {$ENDIF}
  Classes, SysUtils, CustApp, pcap, sockets
  { you can add units after this }, DHCPProcessor,
  protocolheaders, TimeConversion, fingerprint_dhcp, dom, XMLRead, Fingerprint_TCP, TCPConnectionProcessor,
  generaltypes;

type

  TPCapInterface = record
    name:string;
    descr:string;
    addr:PSockAddr;
    netmask:PSockAddr;
    broadadder:PSockAddr;
  end;
  
  //sniffer thread
  TPcapSniff = class(TThread)
  private
    procedure Execute; override;
  public
    pcap_handler : PPCap;
  end;

  { SatoriL }

  SatoriL = class(TCustomApplication)
  protected
    procedure DoRun; override;
  public
    pcap_handler:PPCap;
    sniffThread:TPCapSniff;
    constructor Create(TheOwner: TComponent); override;
    destructor Destroy; override;
    procedure WriteHelp; virtual;
  private
    pcap_interfaces: array of TPcapInterface;
    pcapInterfacesCount:integer;
    procedure ListInterfaces;
    procedure GetInterfaces;
    procedure BindInterface(s:string);
  end;
  
var
  pcaploopint : integer;
  debug, DoAll, DoDHCP, DoTCP, DoEttercap, Dop0f, UniqueOnly:boolean;
  DHCPList, TCPList:TStringList;


{ SatoriL }


procedure packet_handler(user:pchar; header:PPcap_Pkthdr; data:pchar); cdecl;
var
  s:widestring;
  info: TDllInfo;

begin
  if DoDHCP then
    begin
      s:=Parse_DHCP(@Header, Data, @info, debug);
     if s <> '' then
       if UniqueOnly then
         begin
           if DHCPList.IndexOf(s) = -1 then  //not found
             begin
               DHCPList.Add(s);
               DHCPList.Sort;
               writeln(s);
             end;
         end
       else
         writeln(s);
    end;

  if (DoTCP) or (DoEttercap) or (Dop0f) then
    begin
      if DoTCP then info.TCP:=true;
      if DoEttercap then info.Ettercap:=true;
      if Dop0f then info.p0f:=true;
      
      s:=Parse_TCP(@Header, Data, @info, debug);
     if s <> '' then
       if UniqueOnly then
         begin
           if TCPList.IndexOf(s) = -1 then //not found
             begin
               TCPList.Add(s);
               TCPList.Sort;
               writeln(s);
             end;
         end
       else
         writeln(s);
    end;

end;

procedure TPcapSniff.Execute;
begin
  try
    pcaploopint:=pcap_loop(pcap_handler, 0, @packet_handler, nil);
  except
    ;
  end;
end;



procedure SatoriL.DoRun;
var
  //ErrorMsg: String;
  s:string;

begin
  // quick check parameters
{  ErrorMsg:=CheckOptions('h','help');
  if ErrorMsg<>'' then begin
    ShowException(Exception.Create(ErrorMsg));
    Halt;
  end;
}

  //defaults
  DoTCP:=false;
  DoEttercap:=false;
  Dop0f:=false;
  DoDHCP:=false;
  UniqueOnly:=false;
  
  DHCPList:=TStringList.Create;
  TCPList:=TStringList.Create;
  
  DHCPList.Sorted:=true;
  TCPList.Sorted:=true;

  // parse parameters
  if HasOption('h','help') then
    begin
      WriteHelp;
      Halt;
    end;

  if HasOption ('a', 'listall') then
    begin
      GetInterfaces;
      ListInterfaces;
      Halt;
    end;
    
  if HasOption ('d', 'debug') then
    debug:=true
  else
    debug:=false;
    
  if HasOption ('u', 'unique') then
    UniqueOnly:=true
  else
    UniqueOnly:=false;

  if HasOption ('p', 'plugin') then
    begin
      s:=GetOptionValue('p', 'plugin');
       
      if pos('all', s) > 0 then
        begin
          DoDHCP:=true;
          DoTCP:=true;
          Dop0f:=true;
          DoEttercap:=true;
        end;
        
      if pos('dhcp', s) > 0 then DoDHCP:=true;
      if pos('tcp', s) > 0 then DoTCP:=true;
      if pos('ettercap', s) > 0 then DoEttercap:=true;
      if pos('p0f', s) > 0 then Dop0f:=true;

      if DoDHCP then
        begin
          try
            if not LoadDHCP then
              writeln('unable to load dhcp db file');
           except
             on E:exception do writeln(e.Message);
           end;
         end;

      if DoTCP then
        begin
          try
            if not LoadTCP then
              writeln('unable to load tcp db file');
          except
            on E:exception do writeln(e.Message);
          end;
        end;


      if DoEttercap then
        begin
          try
            if not LoadEttercap then
              writeln('unable to load ettercap db file');
          except
            on E:exception do writeln(e.Message);
          end;
        end;


      if Dop0f then
        begin
          try
            if not Loadp0fs then
              writeln('unable to load p0f syn db file');
          except
            on E:exception do writeln(e.Message);
          end;
          
          try
            if not Loadp0fsa then
              writeln('unable to load p0f syn-ack db file');
          except
            on E:exception do writeln(e.Message);
          end;

        end;
    end;
    
  if HasOption ('i', 'interface') then
    begin
      pcaploopint:=-1;

      try
        s:=GetOptionValue('i', 'interface');
      except
        ;
      end;
      
      BindInterface(s);
      
      while pcaploopint = -1 do
        begin
          sleep(1);
        end;
      Halt;
    end
  else
    begin
      if not HasOption ('h', 'help') then
        begin
          writeln('i, interface is a required field!');
          Halt;
        end;
    end;
  
  // stop program loop
  Terminate;
end;

constructor SatoriL.Create(TheOwner: TComponent);
begin
  inherited Create(TheOwner);
  StopOnException:=True;
end;

destructor SatoriL.Destroy;
begin
  inherited Destroy;
end;

procedure SatoriL.WriteHelp;
begin
  { add your help code here }
  writeln('Usage: ',ExeName,' -h, -help [this help screen]');
  writeln('       ',ExeName,' -i, -interface [to bind to an interface name (do not bind to int number)]');
  writeln('       ',ExeName,' -a, -listall [to list available interfaces]');
  writeln('       ',ExeName,' -d, -debug [provide extra info in the output]');
  writeln('       ',ExeName,' -p, -plugin [which type of traffic you want to monitor]');
  writeln('       ',ExeName,' -u, -unique [only show device if it is the first time that "fingerprint" has shown up]');
  writeln('       ',ExeName,'             [all]');
  writeln('       ',ExeName,'             [dhcp,tcp,ettercap,p0f] (no spaces allowed)');
  writeln('       ',ExeName,'             ["dhcp tcp ettercap p0f"]');
  writeln('       ''ctrl-c'' to quit at any time once running');
  writeln('');
  writeln('normal usage:');
  writeln('satori -i eth2 -p "tcp dhcp ettercap p0f"');
  writeln('satori -i eth2 -p tcp,dhcp,ettercap,p0f');
  writeln('');
  writeln('"all" with debug');
  writeln('satori -i eth2 -p all -d');
  writeln('');
  writeln('"all" with debug and only unique ones');
  writeln('satori -i eth2 -p all -d -u');
  writeln('');
end;

procedure SatoriL.BindInterface(s:string);
var
  devName:string;
  errstr:pchar;
  DataLinkType:integer;

begin
  devName:=s;
  
  writeln('Version:  0.1.1  ->  2009-04-07');

  writeln('binding to interface: ' + devName);

  errstr:=pchar(nil);
  
  try
    pcap_handler:=pcap_open_live(pchar(devName), 65536, 1, 1000, errstr);
  except
    on E: exception do writeln(E.Message);
  end;
  
  if not assigned(pcap_handler) then
    begin
      writeln('unable to open adapter: ' + devName);
      halt;
    end;
    
  DataLinkType:=pcap_datalink(pcap_handler);
  writeln('Data Link Type:  (' + IntToStr(DataLinkType) + ') ' + pcap_datalink_val_to_name(DataLinkType));
  
  if DataLinkType <> 1 then
     writeln('Sorry only support EN10MB at this time');
     
  writeln('Version: ' + pchar(pcap_lib_version));
     
  sniffThread:=TPcapSniff.Create(true);
  sniffThread.pcap_handler:=pcap_handler;
  sniffThread.FreeOnTerminate:=true;
  sniffThread.Resume;
end;

procedure SatoriL.ListInterfaces;
var
  k:integer;
  
begin
  for k:=0 to pcapInterfacesCount - 1 do
    writeln(IntToStr(k) + ' : ' + pcap_interfaces[k].name + ' ' + pcap_interfaces[k].descr);
end;

procedure SatoriL.GetInterfaces;
var
  alldevs:PPPCap_if;
  dev:PPCap_if;
  errstr:string;
  k:integer;

begin
  new(alldevs);
  errstr:='';

  try
    if pcap_findalldevs(alldevs, pchar(errstr)) = - 1 then
      begin
        writeln(errstr);
        exit;
      end;

    try
      dev:=alldevs^;

      pcapInterfacesCount:=0;
      while dev <> nil do
        begin
          inc(pcapInterfacesCount);

          k:=length(pcap_interfaces);
          setlength(pcap_interfaces, length(pcap_interfaces) + 1);
          pcap_interfaces[k].name:=dev^.name;
          pcap_interfaces[k].descr:=dev^.description;
          pcap_interfaces[k].addr:=dev^.addresses^.addr;
          pcap_interfaces[k].broadadder:=dev^.addresses^.broadaddr;
          pcap_interfaces[k].netmask:=dev^.addresses^.netmask;

          dev:=dev^.next;
        end;
      pcap_freealldevs(dev);
    except on E: exception do
      writeln('Ran into some issue ' + e.message);
    end;
  finally
    dispose(alldevs);
  end;
end;

var
  Application: SatoriL;
begin
  Application:=SatoriL.Create(nil);
  Application.Title:='Satori Linux Version';
  Application.Run;
  Application.Free;
end.

