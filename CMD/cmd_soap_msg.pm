package cmd_soap_msg;

# preparation
use XML::Compile::WSDL11;      # use WSDL version 1.1
use XML::Compile::SOAP11;      # use SOAP version 1.1
use XML::Compile::Transport::SOAPHTTP;
use Encode;             # para encode e decode
use Bit::Vector;
use Digest::SHA qw(sha256);
use XML::Parser;
use HTTP::Request;
use HTTP::Parser;
use MIME::Base64;

#FUNCIONA
# Função para ativar o debug, permitindo mostrar mensagens enviadas e recebidas do servidor SOAP
sub debug{
	# do you want some trace?
	# transport -> (client) access to request/response for transport layer
	use if ($_[0] == 1), HTTP::Request +trace => [ qw(all) ];
	use if ($_[0] == 1), LWP::UserAgent +trace => [ qw(all) ];
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
	my ($hashtype,$hash)  = @_;

	die "Only SHA256 available" unless $hashtype eq "SHA256";

	@array_strings = ("0x30", "0x31", "0x30", "0x0d", "0x06", "0x09", "0x60", "0x86", "0x48", "0x01", "0x65", "0x03", "0x04", "0x02", "0x01", "0x05", "0x00", "0x04", "0x20");

	my @array_binarios = map {sprintf("%b", hex($_))} @array_strings;

	my $ final_byte_string = join '', @array_binarios;

	#Criação de um dicionário para teste
	%prefix = ("SHA256" => $final_byte_string);

	return $prefix{"SHA256"} . $hash;
}

#FUNCIONA
sub response_parser_certificate{
	$str = $_[0];
	@mycerts = split /<\/?GetCertificateResult>/, $str;
	$certs = $mycerts[1];
	$i=0;
	@aux1;
	
	@temporary_certs = split /-----BEGIN CERTIFICATE-----/, $certs;
	@aux = map {split /-----END CERTIFICATE-----/ ,$_} @temporary_certs;

	$length = @aux;
    die "Wrong number of Certificate" unless $length > 3;
    
	map{MIME::Base64::decode($_);} @aux; # meramente por precaução -> não é preciso
	for ( @aux ) {
		$_ = '-----BEGIN CERTIFICATE-----'. $_ .'-----END CERTIFICATE-----' ;
	}
    
	map {$_ =~ s/&#xD;/ /g} @aux;

	@certificates;
	$certificates[0] = $aux[0];
	$certificates[1] = $aux[2];
	$certificates[2] = $aux[4];

    @certificates;
}

#FUNCIONA
# GetCertificate(applicationId: xsd:base64Binary, userId: xsd:string)
sub  getcertificate{
	$SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/GetCertificate";
	$stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";

	# Só aceitamos nesta função 2 argumentos
	$number_of_args = scalar(@_);
	die "Insuficient args" unless $number_of_args == 2;

	#Obter a escolha do WSDL
	my $wsdl = @_[0];
	#obter a applicationId e o userId dos argumentos passados
	my $appId  = $_[1][6];
	my $userId = $_[1][2];

	#Criação de um dicionário
	$encodedAppId = encode_base64(encode('UTF-8',$appId));
	$body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Header/>" .
                    "<soapenv:Body>" .
                    "<GetCertificate xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<applicationId>" . $encodedAppId . "</applicationId>" .
                    "<userId>" . $userId . "</userId>" .
                    "</GetCertificate>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

    ########################################################
    $request = HTTP::Request->new('POST'=> $stringUrl
    	,[
    		'Accept-Encoding' => 'UTF-8'
    		,'Content-Type' =>'text/xml;charset=utf-8'
    		,SOAPAction => $SOAP_ACTION
    	]
    	,$body);

    $ua = LWP::UserAgent->new;
	$response = $ua->request($request);
	if ($response->is_success) {
		@certificates = response_parser_certificate($response->content);
	} else{
		die "Erro " . $response->status_line . ". Impossível obter certificado.\n";
	}
	@certificates;
}

#FUNCIONA
sub response_parser_signature{
	$str = $_[0];
	@mySignature = split /<\/?a:ProcessId>/, $str;
	return $mySignature[1];
}

#FUNCIONA
# CCMovelSign(request: ns2:SignRequest) -> CCMovelSignResult: ns2:SignStatus
# ns2:SignRequest(ApplicationId: xsd:base64Binary, DocName: xsd:string,
#                  Hash: xsd:base64Binary, Pin: xsd:string, UserId: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                   Message: xsd:string, ProcessId: xsd:string)
sub ccmovelsign{

	$SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/CCMovelSign";
	$stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";
	# Obter a escolha do WSDL
	my $wsdl = @_[0];
	# Obter o tipo de hash a usar
	my $hashtype;
	if(! defined($_[2])){
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
	$hash = encode_base64(encode('UTF-8',hashPrefix($hashtype, $hash)));

	my $appId = $_[1][6];
	my $docName = $_[1][10];
	my $pin = $_[1][3];
	my $userId = $_[1][2];

	$encodedAppId = encode_base64(encode('UTF-8',$appId));

	$body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Body>" .
                    "<CCMovelSign xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<request xmlns:a=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">" .
                    "<a:ApplicationId>" . $encodedAppId . "</a:ApplicationId>" .
                    "<a:DocName>" . $docName . "</a:DocName>" .
                    "<a:Hash>" . $hash . "</a:Hash>" .
                    "<a:Pin>" . $pin . "</a:Pin>" .
                    "<a:UserId>" . $userId . "</a:UserId>" .
                    "</request>" .
                    "</CCMovelSign>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

    ########################################################
    $request = HTTP::Request->new('POST'=> $stringUrl
    	,[
    		'Accept-Encoding' => 'UTF-8'
    		,'Content-Type' =>'text/xml;charset=utf-8'
    		,SOAPAction => $SOAP_ACTION
    	]
    	,$body);
    $ua = LWP::UserAgent->new;
	$response = $ua->request($request);
	if ($response->is_success) {
		$processId = response_parser_signature($response->content);
	} else{
		die"Erro " . $response->status_line . ". Valide o PIN introduzido.\n";
	}
	return $processId;

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
	$SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/CCMovelMultipleSign";
	$stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";
	# Obter a escolha do WSDL
	my $wsdl = @_[0];

	my $appId = $_[1][6];
	my $pin = $_[1][3];
	my $userId = $_[1][2];
	$id1 = '1234';
	$id2 = '1235';
	$body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Body>" .
                    "<CCMovelMultipleSign xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<request xmlns:a=\"http://schemas.datacontract.org/2004/07/Ama.Structures.CCMovelSignature\" xmlns:i=\"http://www.w3.org/2001/XMLSchema-instance\">" .

                    "<a:ApplicationId>" . $encodedAppId . "</a:ApplicationId>" .
                    "<a:Pin>" . $pin . "</a:Pin>" .
                    "<a:UserId>" . $userId . "</a:UserId>" .

                    "<documents>" .

                    "<a:Hash>" . $hash . "</a:Hash>" .
                    "<a:DocName>" . $docName . "</a:DocName>" .
                    "<a:id>" . $id1 . "</a:id>" .

					"<a:Hash>" . $hash . "</a:Hash>" .
                    "<a:DocName>" . $docName . "</a:DocName>" .
                    "<a:id>" . $id2 . "</a:id>" .

                    "</documents>" .
                    "</request>" .
                    "</CCMovelMultipleSign>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

    $request = HTTP::Request->new('POST'=> $stringUrl
    	,[
    		'Accept-Encoding' => 'UTF-8'
    		,'Content-Type' =>'text/xml;charset=utf-8'
    		,SOAPAction => $SOAP_ACTION
    	]
    	,$body);
    $ua = LWP::UserAgent->new;
	$response = $ua->request($request);
	if ($response->is_success) {
		$processId = response_parser_signature($response->content);
	} else{
		die"Erro " . $response->status_line . ". Valide o PIN introduzido.\n";
	}
	return $processId;

}

#FUNCIONA
sub response_parser_otp{
	$str = $_[0];
	@mySignature = split /<\/?a:Signature>/, $str;
	return $mySignature[1];
}

#FUNCIONA
# ValidateOtp(code: xsd:string, processId: xsd:string, applicationId:
#                      xsd:base64Binary) -> ValidateOtpResult: ns2:SignResponse
# ns2:SignResponse(ArrayOfHashStructure: ns2:ArrayOfHashStructure,
#                          Signature: xsd:base64Binary, Status: ns2:SignStatus)
# ns2:ArrayOfHashStructure(HashStructure: ns2:HashStructure[])
# ns2:HashStructure(Hash: xsd:base64Binary, Name: xsd:string, id: xsd:string)
# ns2:SignStatus(Code: xsd:string, Field: xsd:string, FieldValue: xsd:string,
#                                   Message: xsd:string, ProcessId: xsd:string)
sub validate_otp{
	$SOAP_ACTION = "http://Ama.Authentication.Service/CCMovelSignature/ValidateOtp";
	$stringUrl = "https://cmd.autenticacao.gov.pt/Ama.Authentication.Frontend/CCMovelDigitalSignature.svc";

	# Obter a escolha do WSDL
	my $wsdl = @_[0];

	my $appId = $_[1][6];
	my $processId = $_[1][5];
	my $otp = $_[1][4];

	$encodedAppId = encode_base64(encode('UTF-8',$appId));


	$body = "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\">" .
                    "<soapenv:Header/>" .
                    "<soapenv:Body>" .
                    "<ValidateOtp xmlns=\"http://Ama.Authentication.Service/\">" .
                    "<code>" . $otp . "</code>" .
                    "<processId>" . $processId . "</processId>" .
                    "<applicationId>" . $encodedAppId . "</applicationId>" .
                    "</ValidateOtp>" .
                    "</soapenv:Body>" .
                    "</soapenv:Envelope>";

	$request = HTTP::Request->new('POST'=> $stringUrl
    	,[
    		'Accept-Encoding' => 'UTF-8'
    		,'Content-Type' =>'text/xml;charset=utf-8'
    		,SOAPAction => $SOAP_ACTION
    	]
    	,$body);

    $ua = LWP::UserAgent->new;
	$response = $ua->request($request);
	if ($response->is_success) {
		$signature = response_parser_otp($response->content);
	} else{
		die "Erro " . $response->status_line . ". Impossível obter certificado.\n";
	}
	return $signature;
}


# este parâmetro tem de existir por sintaxe do perl
1;