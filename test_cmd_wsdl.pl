
use Getopt::ArgParse;
use File::Basename;
use Crypt::X509;

use cmd_config;
use cmd_soap_msg;

$TEXT = 'test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)'
$VERSION = 'version: 1.0'
$APPLICATION_ID = cmd_config::get_appid()

sub main{
	#Função main do programa.

	#Verifica se input é um número natural
    die 'Configure o APPLICATION_ID' unless $APPLICATION_ID =~ /^\d+$/;
    
    $number_of_args = scalar(@_);

    my($filename, $dirs, $suffix) = fileparse($path)
    die 'Use -h for usage:\n  ', $filename, '-h for all operations\n  ', $filename,
    	'<oper1> -h for usage of operation <oper1>' unless $number_of_args > 1

    #Faz o parser dos argumentos recebidos
    $args = args_parse()

    $client = cmd_soap_msg::get_wsdl(args.prod)
    my $opt = _[0] # opção escolhida pelo utilizador
    if $opt == 'test'{
    	testall($client,$args)
    } elsif $opt == 'gc'{
    	print cmd_soap_msg::getcertificate($client,$args)
    } elsif $opt == 'ms'{
    	print cmd_soap_msg::ccmovelsign($client,$args)
    } elsif $opt == 'mms'{
    	print cmd_soap_msg::ccmovelmultiplesign($client,$args)
    } elsif $opt == 'otp'{
    	print cmd_soap_msg::validate_otp($client,$args)
    } else{
    	die "Select a proper Option!!" 
    }
}

sub args_parse{
	#Criação do parser
	$parser = Getopt::ArgParse->new_parser(
       		prog        => 'CCMovelDigitalSignature Service',
       		help        => 'Signature CMD (SCMD) operations',
       		description => $TEXT
   			epilog      => '------FINISHED------',
		);
	$parser->add_argument(
		'--version',
		help        => 'show program version',
        action      => sub { return $VERSION }
        );

	# Adição de subcomandos
	$parser->add_subparsers(
  			title       => 'Subcommands',
  			description => 'Subcomands for a more efective code usage',
		);

	# GetCertificate command
	$gc_parser = $parser->add_parser(
		'GetCertificate',
		help        => 'Get user certificate',
		description => 'Get user certificate',
		aliases     => [qw(gc)],
		parents     => [ $common_args ], # inherit common args from
                                         # $common_args
    	);
    $gc_parser->add_args(
    	['user', action => 'store', help => 'user phone number (+XXX NNNNNNNNN)'],
    	['applicationId', action => 'store', help => 'CMD ApplicationId', default => $APPLICATION_ID],
    	['-prod', action => 'store_true', help => 'Use production SCMD service (preproduction SCMD service used by default)'],
    	['-D', '--debug', action => 'store_true', help => 'show debug information']
    	);

    # CCMovelSign command
    $ms_parser = $parser->add_parser(
		'CCMovelSign',
		help        => 'Start signature process',
		description => 'Start signature process',
		aliases     => [qw(ms)],
		parents     => [ $common_args ], # inherit common args from
                                         # $common_args
    	);
    $ms_parser->add_args(
    	['user', action => 'store',help => 'user phone number (+XXX NNNNNNNNN)'],
    	['pin', action => 'store', help => 'CMD signature PIN'],
    	['applicationId', action => 'store', help => 'CMD ApplicationId', default => $APPLICATION_ID],
    	['-prod', action => 'store_true', help => 'Use production SCMD service (preproduction SCMD service used by default)'],
    	['-D', '--debug', action => 'store_true', help => 'show debug information']
    	);

    # CCMovelMultipleSign command
    $mms_parser = $parser->add_parser(
		'CCMovelMultipleSign',
		help        => 'Start multiple signature process',
		description => 'Start multiple signature process',
		aliases     => [qw(mms)],
		parents     => [ $common_args ], # inherit common args from
                                         # $common_args
    	);
    $mms_parser->add_args(
    	['user', action => 'store',help => 'user phone number (+XXX NNNNNNNNN)'],
    	['pin', action => 'store', help => 'CMD signature PIN'],
    	['applicationId', action => 'store', help => 'CMD ApplicationId', default => $APPLICATION_ID],
    	['-prod', action => 'store_true', help => 'Use production SCMD service (preproduction SCMD service used by default)'],
    	['-D', '--debug', action => 'store_true', help => 'show debug information']
    	);

    # ValidateOtp command
    $val_parser = $parser->add_parser(
		'ValidateOtp',
		help        => 'Validate OTP',
		description => 'Validate OTP',
		aliases     => [qw(otp)],
		parents     => [ $common_args ], # inherit common args from
                                         # $common_args
    	);
    $val_parser->add_args(
    	['OTP', action => 'store', help => 'OTP received in your device'],
    	['ProcessId', action => 'store', help => 'ProcessID received in the answer of the CCMovelSign/CCMovelMultipleSign command'],
    	['applicationId', action => 'store', help => 'CMD ApplicationId', default => $APPLICATION_ID],
    	['-prod', action => 'store_true', help => 'Use production SCMD service (preproduction SCMD service used by default)'],
    	['-D', '--debug', action => 'store_true', help => 'show debug information']
    	);

    # testall command
    $test_parser = $parser->add_parser(
		'TestAll',
		help        => 'Automatically test all commands',
		description => 'Automatically test all commands',
		aliases     => [qw('test')],
		parents     => [ $common_args ], # inherit common args from
                                         # $common_args
    	);
    $test_parser->add_args(
    	['file', action => 'store', help => 'file'],
    	['user', action => 'store',help => 'user phone number (+XXX NNNNNNNNN)'],
    	['pin', action => 'store', help => 'CMD signature PIN'],
    	['applicationId', action => 'store', help => 'CMD ApplicationId', default => $APPLICATION_ID],
    	['-prod', action => 'store_true', help => 'Use production SCMD service (preproduction SCMD service used by default)'],
    	['-D', '--debug', action => 'store_true', help => 'show debug information']
    	);

    return parser
}

# Testa todos os comandos
sub testall{
	print '$TEXT \n  $VERSION'
    print '\n+++ Test All inicializado +++\n'
    print ' 0% ... Leitura de argumentos da linha de comando - file: $args.file user: $args.user pin: $args.pin')
    print('10% ... A contactar servidor SOAP CMD para operação GetCertificate')
    my ($client, $args) = @_;
    $cmd_certs = cmd_soap_msg::getcertificate($client, $args)
    if (defined $cmd_certs){
    	$decoded = Crypt::X509->new(cert => $cmd_certs);
    	%certs_chain = ('user' => ,'ca' => , 'root' =>)








    } else{
    		die 'Impossível obter certificado'
    	}


}