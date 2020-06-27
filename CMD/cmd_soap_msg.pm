package cmd_soap_msg;

# preparation
use SOAP::Lite;
use SOAP::WSDL;
use XML::Compile::WSDL11;      # use WSDL version 1.1
use XML::Compile::SOAP11;      # use SOAP version 1.1
use XML::Compile::Transport::SOAPHTTP;
use Encode;             # para encode e decode
use Bit::Vector;
use Digest::SHA qw(sha256);





# Função para ativar o debug, permitindo mostrar mensagens enviadas e recebidas do servidor SOAP
sub debug{
	# do you want some trace?
	# transport -> (client) access to request/response for transport layer
	use if ($_[0] == 1), SOAP::Lite +trace => [ qw(transport) ];
}

#FUNCIONA
# Função que devolve o cliente de ligação (preprod ou prod) ao servidor SOAP da CMD
sub get_wsdl{

	@wsdl = ('https://preprod.cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl',
	        'https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc?wsdl');


	my ($input) = @_[0];

	# não há necessidade de testar o prod por este ser 0 ou 1 sempre 
	# garantido pelo Getopt ao fazer o parsing do @ARGV


	$choice = int($input);
 

	return $wsdl[$choice]
}

# FUNCIONA
# Devolve a hash acrescentada do prefixo do tipo de hash utilizada
sub hashPrefix{
	#obter o hashtype e a hash dos argumentos passados
	my $hashtype  = @_[0];
	my $hash = @_[1];

	die "Only SHA256 available" unless $hashtype eq "SHA256";

	@array_strings = ("0x30", "0x31", "0x30", "0x0d", "0x06", "0x09", "0x60", "0x86", "0x48", "0x01", "0x65", "0x03", "0x04", "0x02", "0x01", "0x05", "0x00", "0x04", "0x20");

	my @array_binarios = map {sprintf("%b", hex($_))} @array_strings;

	my $ final_byte_string = join '', @array_binarios;

	#Criação de um dicionário para teste
	%prefix = ("SHA256" => $final_byte_string);

	return $prefix{"SHA256"} . $hash;
}

#A TESTAR
# GetCertificate(applicationId: xsd:base64Binary, userId: xsd:string)
sub  getcertificate{

	# Só aceitamos nesta função 2 argumentos
	$number_of_args = scalar(@_);
	die "Insuficient args" unless $number_of_args == 2;

	#Obter a escolha do WSDL
	my $res = @_[0];
	#obter a applicationId e o userId dos argumentos passados
	my $appId  = $_[1][6];
	my $userId = $_[1][2];

	# Verifica se todas as strings inseridas são números naturais e não têm caracters estranhos
	die "Only numbers are accepted for UserId!!" unless ($userId =~ /\+\d+/);

	#Criação de um dicionário para teste
	$encodedAppId = encode('UTF-8',$appId);
	%data = ('applicationId' => $encodedAppId , 'userId' => $userId);
	#método a ser usado
	my $method = "GetCertificate";

	#Criação do cliente
	$server =  SOAP::Lite->new(proxy => $res);
	#alternativa => $server =  SOAP::Lite->service($res);
	#Obtenção do certificado
	$answer = $server -> call($method,%data) -> result;
	
	return $answer
}



# CCMovelSign(request: ns2:SignRequest) -> CCMovelSignResult: ns2:SignStatus
# ns2:SignRequest(ApplicationId: xsd:base64Binary, DocName: xsd:string,
#                  Hash: xsd:base64Binary, Pin: xsd:string, UserId: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                   Message: xsd:string, ProcessId: xsd:string)
sub ccmovelsign{

	# Obter a escolha do WSDL
	my $res = @_[0];
	# Obter o tipo de hash a usar
	my $hashtype;
	if(! defined $_[2]){
		$hashtype = "SHA256";
	} else{
		$hashtype = $_[2];
	}
	# Obtenção do ficheiro
	if(! defined $_[1][10]){
		$_[1][10] = 'docname teste';
	}
	# Obtenção do hash 
	my $hash = $_[1][9];
	if(! defined $_[1][9]){
		$message = sprintf("%b",'Nobody inspects the spammish repetition');
		$hash = sha256($message);
	}
	$hash = hashPrefix(hashtype, $hash);

	my $appId = $_[1][6];
	my $docName = $_[1][10];
	my $pin = $_[1][3];
	my $userId = $_[1][2];


	#Criação do cliente
	$server =  SOAP::Lite->new(proxy => $res);
	#método a ser usado
	my $method = "CCMovelSign";

	my %request_data;
	$request_data{'request'}{'ApplicationId'} = encode('UTF-8',$appId);
	$request_data{'request'}{'DocName'} = $docName;
	$request_data{'request'}{'Hash'} = $hash;
	$request_data{'request'}{'Pin'} = $pin;
	$request_data{'request'}{'UserId'} =  $userId;

	#Obtenção da resposta
	$answer = $server -> call($method,%request) -> result;
	return $answer;
}


# CCMovelMultipleSign(request: ns2:MultipleSignRequest,
#                              documents: ns2:ArrayOfHashStructure)
#                                  -> CCMovelMultipleSignResult: ns2:SignStatus
# ns2:MultipleSignRequest(ApplicationId: xsd:base64Binary, Pin: xsd:string,
#                                                           UserId: xsd:string)
# ns2:ArrayOfHashStructure(HashStructure: ns2:HashStructure[])
# ns2:HashStructure(Hash: xsd:base64Binary, Name: xsd:string, id: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                   Message: xsd:string, ProcessId: xsd:string)
sub ccmovelmultiplesign{
	# Obter a escolha do WSDL
	my $res = @_[0];
	#Criação do cliente
	$server =  SOAP::Lite->new(proxy => $res);
	#método a ser usado
	my $method = "CCMovelMultipleSign";


	my $appId = $_[1][6];
	my $pin = $_[1][3];
	my $userId = $_[1][2];

	#Criação do pedido
	my %request_data;
	$request_data{'request'}{'ApplicationId'} = encode('UTF-8',$appId);
	$request_data{'request'}{'Pin'} = $pin;
	$request_data{'request'}{'UserId'} = $userId;

	my $first_message = sprintf("%b",'Nobody inspects the spammish repetition');
	my $second_message = sprintf("%b",'Always inspect the spammish repetition');
	$first_hash = sha256($first_message);
	$second_hash = sha256($second_message);

	%first_hash_structure = ('Hash' => $first_hash, 'Name' => 'docname teste1', 'id' => '1234');
	%second_hash_structure = ('Hash' => $second_hash, 'Name' => 'docname teste2', 'id' => '1235');

	@hash_structure = ($first_hash_structure,$second_hash_structure);

	$request_data{'documents'}{'HashStructure'} = @hash_structure;

	#Obtenção da resposta
	$answer = $server -> call($method,%request_data) -> result;
	return $answer;
}

# ValidateOtp(code: xsd:string, processId: xsd:string, applicationId:
#                      xsd:base64Binary) -> ValidateOtpResult: ns2:SignResponse
# ns2:SignResponse(ArrayOfHashStructure: ns2:ArrayOfHashStructure,
#                          Signature: xsd:base64Binary, Status: ns2:SignStatus)
# ns2:ArrayOfHashStructure(HashStructure: ns2:HashStructure[])
# ns2:HashStructure(Hash: xsd:base64Binary, Name: xsd:string, id: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                                   Message: xsd:string, ProcessId: xsd:string)
sub validate_otp{
	# Obter a escolha do WSDL
	my $res = @_[0];

	my $appId = $_[1][6];
	my $processId = $_[1][5];
	my $code = $_[1][4];

	my %request_data;
	$request_data{'applicationId'} = encode('UTF-8',$appId);
	$request_data{'processId'} = $processId;
	$request_data{'code'} = $code;

	#Criação do cliente
	$server =  SOAP::Lite->new(proxy => $res);
	#método a ser usado
	my $method = "ValidateOtp";
	#Obtenção da resposta
	$answer = $server -> call($method,%request_data) -> result;
	return $answer;
}


# este parâmetro tem de existir por sintaxe do perl
1;