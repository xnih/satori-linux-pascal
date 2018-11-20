
{***********************************************************************}
{                                                                       }
{                           XML Data Binding                            }
{                                                                       }
{         Generated on: 12/24/2008 10:38:29 AM                          }
{       Generated from: C:\projects\satori\2brun\fingerprint\dhcp.xml   }
{   Settings stored in: C:\projects\satori\2brun\fingerprint\dhcp.xdb   }
{                                                                       }
{***********************************************************************}

unit dhcpXML;

interface

uses dom, XMLRead, xmlintf;

type

{ Forward Decls }

  IXMLDHCPType = interface;
  IXMLFingerprintsType = interface;
  IXMLFingerprintType = interface;
  IXMLDhcp_testsType = interface;
  IXMLTestType = interface;

{ IXMLDHCPType }

  IXMLDHCPType = interface(IXMLNode)
    ['{DC0B60C8-FD0D-45C8-A619-E9C7808289A9}']
    { Property Accessors }
    function Get_Created: WideString;
    function Get_Last_updated: WideString;
    function Get_Author: WideString;
    function Get_Fingerprints: IXMLFingerprintsType;
    procedure Set_Created(Value: WideString);
    procedure Set_Last_updated(Value: WideString);
    procedure Set_Author(Value: WideString);
    { Methods & Properties }
    property Created: WideString read Get_Created write Set_Created;
    property Last_updated: WideString read Get_Last_updated write Set_Last_updated;
    property Author: WideString read Get_Author write Set_Author;
    property Fingerprints: IXMLFingerprintsType read Get_Fingerprints;
  end;

{ IXMLFingerprintsType }

  IXMLFingerprintsType = interface(IXMLNodeCollection)
    ['{99C6DD31-EF55-4C84-A973-7BF06C7A2768}']
    { Property Accessors }
    function Get_Fingerprint(Index: Integer): IXMLFingerprintType;
    { Methods & Properties }
    function Add: IXMLFingerprintType;
    function Insert(const Index: Integer): IXMLFingerprintType;
    property Fingerprint[Index: Integer]: IXMLFingerprintType read Get_Fingerprint; default;
  end;

{ IXMLFingerprintType }

  IXMLFingerprintType = interface(IXMLNode)
    ['{DED5337A-3ED1-4AEA-B26A-6DA80E6F052E}']
    { Property Accessors }
    function Get_Name: WideString;
    function Get_Os_name: WideString;
    function Get_Os_class: WideString;
    function Get_Os_vendor: WideString;
    function Get_Os_url: WideString;
    function Get_Device_type: WideString;
    function Get_Device_vendor: WideString;
    function Get_Device_url: WideString;
    function Get_Comments: WideString;
    function Get_Author: WideString;
    function Get_Last_updated: WideString;
    function Get_Dhcp_tests: IXMLDhcp_testsType;
    procedure Set_Name(Value: WideString);
    procedure Set_Os_name(Value: WideString);
    procedure Set_Os_class(Value: WideString);
    procedure Set_Os_vendor(Value: WideString);
    procedure Set_Os_url(Value: WideString);
    procedure Set_Device_type(Value: WideString);
    procedure Set_Device_vendor(Value: WideString);
    procedure Set_Device_url(Value: WideString);
    procedure Set_Comments(Value: WideString);
    procedure Set_Author(Value: WideString);
    procedure Set_Last_updated(Value: WideString);
    { Methods & Properties }
    property Name: WideString read Get_Name write Set_Name;
    property Os_name: WideString read Get_Os_name write Set_Os_name;
    property Os_class: WideString read Get_Os_class write Set_Os_class;
    property Os_vendor: WideString read Get_Os_vendor write Set_Os_vendor;
    property Os_url: WideString read Get_Os_url write Set_Os_url;
    property Device_type: WideString read Get_Device_type write Set_Device_type;
    property Device_vendor: WideString read Get_Device_vendor write Set_Device_vendor;
    property Device_url: WideString read Get_Device_url write Set_Device_url;
    property Comments: WideString read Get_Comments write Set_Comments;
    property Author: WideString read Get_Author write Set_Author;
    property Last_updated: WideString read Get_Last_updated write Set_Last_updated;
    property Dhcp_tests: IXMLDhcp_testsType read Get_Dhcp_tests;
  end;

{ IXMLDhcp_testsType }

  IXMLDhcp_testsType = interface(IXMLNodeCollection)
    ['{C074D315-7677-4318-BD31-546428C15FD6}']
    { Property Accessors }
    function Get_Test(Index: Integer): IXMLTestType;
    { Methods & Properties }
    function Add: IXMLTestType;
    function Insert(const Index: Integer): IXMLTestType;
    property Test[Index: Integer]: IXMLTestType read Get_Test; default;
  end;

{ IXMLTestType }

  IXMLTestType = interface(IXMLNode)
    ['{2517F400-74FB-467E-B0EE-CFDD3AB2A394}']
    { Property Accessors }
    function Get_Weight: Integer;
    function Get_Matchtype: WideString;
    function Get_Dhcptype: WideString;
    function Get_Dhcpoptions: WideString;
    function Get_Dhcpoption55: WideString;
    function Get_Dhcpvendorcode: WideString;
    function Get_Ipttl: Integer;
    function Get_Dhcpoption57: Integer;
    function Get_Dhcpoption51: Integer;
    procedure Set_Weight(Value: Integer);
    procedure Set_Matchtype(Value: WideString);
    procedure Set_Dhcptype(Value: WideString);
    procedure Set_Dhcpoptions(Value: WideString);
    procedure Set_Dhcpoption55(Value: WideString);
    procedure Set_Dhcpvendorcode(Value: WideString);
    procedure Set_Ipttl(Value: Integer);
    procedure Set_Dhcpoption57(Value: Integer);
    procedure Set_Dhcpoption51(Value: Integer);
    { Methods & Properties }
    property Weight: Integer read Get_Weight write Set_Weight;
    property Matchtype: WideString read Get_Matchtype write Set_Matchtype;
    property Dhcptype: WideString read Get_Dhcptype write Set_Dhcptype;
    property Dhcpoptions: WideString read Get_Dhcpoptions write Set_Dhcpoptions;
    property Dhcpoption55: WideString read Get_Dhcpoption55 write Set_Dhcpoption55;
    property Dhcpvendorcode: WideString read Get_Dhcpvendorcode write Set_Dhcpvendorcode;
    property Ipttl: Integer read Get_Ipttl write Set_Ipttl;
    property Dhcpoption57: Integer read Get_Dhcpoption57 write Set_Dhcpoption57;
    property Dhcpoption51: Integer read Get_Dhcpoption51 write Set_Dhcpoption51;
  end;

{ Forward Decls }

  TXMLDHCPType = class;
  TXMLFingerprintsType = class;
  TXMLFingerprintType = class;
  TXMLDhcp_testsType = class;
  TXMLTestType = class;

{ TXMLDHCPType }

  TXMLDHCPType = class(TXMLNode, IXMLDHCPType)
  protected
    { IXMLDHCPType }
    function Get_Created: WideString;
    function Get_Last_updated: WideString;
    function Get_Author: WideString;
    function Get_Fingerprints: IXMLFingerprintsType;
    procedure Set_Created(Value: WideString);
    procedure Set_Last_updated(Value: WideString);
    procedure Set_Author(Value: WideString);
  public
    procedure AfterConstruction; override;
  end;

{ TXMLFingerprintsType }

  TXMLFingerprintsType = class(TXMLNodeCollection, IXMLFingerprintsType)
  protected
    { IXMLFingerprintsType }
    function Get_Fingerprint(Index: Integer): IXMLFingerprintType;
    function Add: IXMLFingerprintType;
    function Insert(const Index: Integer): IXMLFingerprintType;
  public
    procedure AfterConstruction; override;
  end;

{ TXMLFingerprintType }

  TXMLFingerprintType = class(TXMLNode, IXMLFingerprintType)
  protected
    { IXMLFingerprintType }
    function Get_Name: WideString;
    function Get_Os_name: WideString;
    function Get_Os_class: WideString;
    function Get_Os_vendor: WideString;
    function Get_Os_url: WideString;
    function Get_Device_type: WideString;
    function Get_Device_vendor: WideString;
    function Get_Device_url: WideString;
    function Get_Comments: WideString;
    function Get_Author: WideString;
    function Get_Last_updated: WideString;
    function Get_Dhcp_tests: IXMLDhcp_testsType;
    procedure Set_Name(Value: WideString);
    procedure Set_Os_name(Value: WideString);
    procedure Set_Os_class(Value: WideString);
    procedure Set_Os_vendor(Value: WideString);
    procedure Set_Os_url(Value: WideString);
    procedure Set_Device_type(Value: WideString);
    procedure Set_Device_vendor(Value: WideString);
    procedure Set_Device_url(Value: WideString);
    procedure Set_Comments(Value: WideString);
    procedure Set_Author(Value: WideString);
    procedure Set_Last_updated(Value: WideString);
  public
    procedure AfterConstruction; override;
  end;

{ TXMLDhcp_testsType }

  TXMLDhcp_testsType = class(TXMLNodeCollection, IXMLDhcp_testsType)
  protected
    { IXMLDhcp_testsType }
    function Get_Test(Index: Integer): IXMLTestType;
    function Add: IXMLTestType;
    function Insert(const Index: Integer): IXMLTestType;
  public
    procedure AfterConstruction; override;
  end;

{ TXMLTestType }

  TXMLTestType = class(TXMLNode, IXMLTestType)
  protected
    { IXMLTestType }
    function Get_Weight: Integer;
    function Get_Matchtype: WideString;
    function Get_Dhcptype: WideString;
    function Get_Dhcpoptions: WideString;
    function Get_Dhcpoption55: WideString;
    function Get_Dhcpvendorcode: WideString;
    function Get_Ipttl: Integer;
    function Get_Dhcpoption57: Integer;
    function Get_Dhcpoption51: Integer;
    procedure Set_Weight(Value: Integer);
    procedure Set_Matchtype(Value: WideString);
    procedure Set_Dhcptype(Value: WideString);
    procedure Set_Dhcpoptions(Value: WideString);
    procedure Set_Dhcpoption55(Value: WideString);
    procedure Set_Dhcpvendorcode(Value: WideString);
    procedure Set_Ipttl(Value: Integer);
    procedure Set_Dhcpoption57(Value: Integer);
    procedure Set_Dhcpoption51(Value: Integer);
  end;

{ Global Functions }

function GetDHCP(Doc: IXMLDocument): IXMLDHCPType;
function LoadDHCP(const FileName: WideString): IXMLDHCPType;
function NewDHCP: IXMLDHCPType;

const
  TargetNamespace = '';

implementation

{ Global Functions }

function GetDHCP(Doc: IXMLDocument): IXMLDHCPType;
begin
  Result := Doc.GetDocBinding('DHCP', TXMLDHCPType, TargetNamespace) as IXMLDHCPType;
end;

function LoadDHCP(const FileName: WideString): IXMLDHCPType;
begin
  Result := LoadXMLDocument(FileName).GetDocBinding('DHCP', TXMLDHCPType, TargetNamespace) as IXMLDHCPType;
end;

function NewDHCP: IXMLDHCPType;
begin
  Result := NewXMLDocument.GetDocBinding('DHCP', TXMLDHCPType, TargetNamespace) as IXMLDHCPType;
end;

{ TXMLDHCPType }

procedure TXMLDHCPType.AfterConstruction;
begin
  RegisterChildNode('fingerprints', TXMLFingerprintsType);
  inherited;
end;

function TXMLDHCPType.Get_Created: WideString;
begin
  Result := AttributeNodes['created'].Text;
end;

procedure TXMLDHCPType.Set_Created(Value: WideString);
begin
  SetAttribute('created', Value);
end;

function TXMLDHCPType.Get_Last_updated: WideString;
begin
  Result := AttributeNodes['last_updated'].Text;
end;

procedure TXMLDHCPType.Set_Last_updated(Value: WideString);
begin
  SetAttribute('last_updated', Value);
end;

function TXMLDHCPType.Get_Author: WideString;
begin
  Result := AttributeNodes['author'].Text;
end;

procedure TXMLDHCPType.Set_Author(Value: WideString);
begin
  SetAttribute('author', Value);
end;

function TXMLDHCPType.Get_Fingerprints: IXMLFingerprintsType;
begin
  Result := ChildNodes['fingerprints'] as IXMLFingerprintsType;
end;

{ TXMLFingerprintsType }

procedure TXMLFingerprintsType.AfterConstruction;
begin
  RegisterChildNode('fingerprint', TXMLFingerprintType);
  ItemTag := 'fingerprint';
  ItemInterface := IXMLFingerprintType;
  inherited;
end;

function TXMLFingerprintsType.Get_Fingerprint(Index: Integer): IXMLFingerprintType;
begin
  Result := List[Index] as IXMLFingerprintType;
end;

function TXMLFingerprintsType.Add: IXMLFingerprintType;
begin
  Result := AddItem(-1) as IXMLFingerprintType;
end;

function TXMLFingerprintsType.Insert(const Index: Integer): IXMLFingerprintType;
begin
  Result := AddItem(Index) as IXMLFingerprintType;
end;

{ TXMLFingerprintType }

procedure TXMLFingerprintType.AfterConstruction;
begin
  RegisterChildNode('dhcp_tests', TXMLDhcp_testsType);
  inherited;
end;

function TXMLFingerprintType.Get_Name: WideString;
begin
  Result := AttributeNodes['name'].Text;
end;

procedure TXMLFingerprintType.Set_Name(Value: WideString);
begin
  SetAttribute('name', Value);
end;

function TXMLFingerprintType.Get_Os_name: WideString;
begin
  Result := AttributeNodes['os_name'].Text;
end;

procedure TXMLFingerprintType.Set_Os_name(Value: WideString);
begin
  SetAttribute('os_name', Value);
end;

function TXMLFingerprintType.Get_Os_class: WideString;
begin
  Result := AttributeNodes['os_class'].Text;
end;

procedure TXMLFingerprintType.Set_Os_class(Value: WideString);
begin
  SetAttribute('os_class', Value);
end;

function TXMLFingerprintType.Get_Os_vendor: WideString;
begin
  Result := AttributeNodes['os_vendor'].Text;
end;

procedure TXMLFingerprintType.Set_Os_vendor(Value: WideString);
begin
  SetAttribute('os_vendor', Value);
end;

function TXMLFingerprintType.Get_Os_url: WideString;
begin
  Result := AttributeNodes['os_url'].Text;
end;

procedure TXMLFingerprintType.Set_Os_url(Value: WideString);
begin
  SetAttribute('os_url', Value);
end;

function TXMLFingerprintType.Get_Device_type: WideString;
begin
  Result := AttributeNodes['device_type'].Text;
end;

procedure TXMLFingerprintType.Set_Device_type(Value: WideString);
begin
  SetAttribute('device_type', Value);
end;

function TXMLFingerprintType.Get_Device_vendor: WideString;
begin
  Result := AttributeNodes['device_vendor'].Text;
end;

procedure TXMLFingerprintType.Set_Device_vendor(Value: WideString);
begin
  SetAttribute('device_vendor', Value);
end;

function TXMLFingerprintType.Get_Device_url: WideString;
begin
  Result := AttributeNodes['device_url'].Text;
end;

procedure TXMLFingerprintType.Set_Device_url(Value: WideString);
begin
  SetAttribute('device_url', Value);
end;

function TXMLFingerprintType.Get_Comments: WideString;
begin
  Result := AttributeNodes['comments'].Text;
end;

procedure TXMLFingerprintType.Set_Comments(Value: WideString);
begin
  SetAttribute('comments', Value);
end;

function TXMLFingerprintType.Get_Author: WideString;
begin
  Result := AttributeNodes['author'].Text;
end;

procedure TXMLFingerprintType.Set_Author(Value: WideString);
begin
  SetAttribute('author', Value);
end;

function TXMLFingerprintType.Get_Last_updated: WideString;
begin
  Result := AttributeNodes['last_updated'].Text;
end;

procedure TXMLFingerprintType.Set_Last_updated(Value: WideString);
begin
  SetAttribute('last_updated', Value);
end;

function TXMLFingerprintType.Get_Dhcp_tests: IXMLDhcp_testsType;
begin
  Result := ChildNodes['dhcp_tests'] as IXMLDhcp_testsType;
end;

{ TXMLDhcp_testsType }

procedure TXMLDhcp_testsType.AfterConstruction;
begin
  RegisterChildNode('test', TXMLTestType);
  ItemTag := 'test';
  ItemInterface := IXMLTestType;
  inherited;
end;

function TXMLDhcp_testsType.Get_Test(Index: Integer): IXMLTestType;
begin
  Result := List[Index] as IXMLTestType;
end;

function TXMLDhcp_testsType.Add: IXMLTestType;
begin
  Result := AddItem(-1) as IXMLTestType;
end;

function TXMLDhcp_testsType.Insert(const Index: Integer): IXMLTestType;
begin
  Result := AddItem(Index) as IXMLTestType;
end;

{ TXMLTestType }

function TXMLTestType.Get_Weight: Integer;
begin
  Result := AttributeNodes['weight'].NodeValue;
end;

procedure TXMLTestType.Set_Weight(Value: Integer);
begin
  SetAttribute('weight', Value);
end;

function TXMLTestType.Get_Matchtype: WideString;
begin
  Result := AttributeNodes['matchtype'].Text;
end;

procedure TXMLTestType.Set_Matchtype(Value: WideString);
begin
  SetAttribute('matchtype', Value);
end;

function TXMLTestType.Get_Dhcptype: WideString;
begin
  Result := AttributeNodes['dhcptype'].Text;
end;

procedure TXMLTestType.Set_Dhcptype(Value: WideString);
begin
  SetAttribute('dhcptype', Value);
end;

function TXMLTestType.Get_Dhcpoptions: WideString;
begin
  Result := AttributeNodes['dhcpoptions'].Text;
end;

procedure TXMLTestType.Set_Dhcpoptions(Value: WideString);
begin
  SetAttribute('dhcpoptions', Value);
end;

function TXMLTestType.Get_Dhcpoption55: WideString;
begin
  Result := AttributeNodes['dhcpoption55'].Text;
end;

procedure TXMLTestType.Set_Dhcpoption55(Value: WideString);
begin
  SetAttribute('dhcpoption55', Value);
end;

function TXMLTestType.Get_Dhcpvendorcode: WideString;
begin
  Result := AttributeNodes['dhcpvendorcode'].Text;
end;

procedure TXMLTestType.Set_Dhcpvendorcode(Value: WideString);
begin
  SetAttribute('dhcpvendorcode', Value);
end;

function TXMLTestType.Get_Ipttl: Integer;
begin
  Result := AttributeNodes['ipttl'].NodeValue;
end;

procedure TXMLTestType.Set_Ipttl(Value: Integer);
begin
  SetAttribute('ipttl', Value);
end;

function TXMLTestType.Get_Dhcpoption57: Integer;
begin
  Result := AttributeNodes['dhcpoption57'].NodeValue;
end;

procedure TXMLTestType.Set_Dhcpoption57(Value: Integer);
begin
  SetAttribute('dhcpoption57', Value);
end;

function TXMLTestType.Get_Dhcpoption51: Integer;
begin
  Result := AttributeNodes['dhcpoption51'].NodeValue;
end;

procedure TXMLTestType.Set_Dhcpoption51(Value: Integer);
begin
  SetAttribute('dhcpoption51', Value);
end;

end.

