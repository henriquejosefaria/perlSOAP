use Getopt::ArgParse;
use File::Basename;
use Crypt::X509;
use Crypt::OpenSSL::RSA;
use File::Slurp;
use Try::Tiny;
use Digest::SHA qw(sha256);
use MIME::Base64;

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

    return parser.parse_args()
}

# Testa todos os comandos
sub testall{
    print '$TEXT \n  $VERSION';
    print '\n+++ Test All inicializado +++\n';
    print ' 0% ... Leitura de argumentos da linha de comando - file: $args.file user: $args.user pin: $args.pin';
    print '10% ... A contactar servidor SOAP CMD para operação GetCertificate';
    my ($client, $args) = @_;
    $cmd_certs = cmd_soap_msg::getcertificate($client, $args);
    if (defined $cmd_certs){
        $decoded = Crypt::X509->new(cert => $cmd_certs);
        if ($decoded->notBefore < time()) {
            die "Certificate: not yet valid!";
        }
        if ($decoded->not_after < time()) {
            die "Certificate: invalid expiration time!";
        }
        %certs_chain = ('user' => $decoded->Subject, 'ca' => $decoded->Issuer, 'root' => $decoded->authorityCertIssuer);
        print '20% ... Certificado emitido para $certs_chain[\'user\'] pela Entidade de Certificação certs_chain[\'ca\'] na hierarquia do certs_chain[\'root\']';
        print '30% ... Leitura do ficheiro $args.file';
        try{
            my $file_content = read_file(args->file);
        } catch{
            die 'Ficheiro não encontrado.';
        }
        print '40% ... Geração de hash do ficheiro $args.file';

        $args->hash = sha256($file_content) # Geração do Digest
        $decoded_arg = decode_base64(encode_base64($args->hash));
        print '50% ... Hash gerada (em base64): $decoded_arg';
        print '60% ... A contactar servidor SOAP CMD para operação CCMovelSign';
        $args->docName = args->file;
        @res = cmd_soap_msg::ccmovelsign($client, $args);
        if (@res['Code'] != '200'){
            die 'Erro $res[\'Code\']. Valide o PIN introduzido.';
        }
        print '70% ... ProcessID devolvido pela operação CCMovelSign: $res['ProcessId']';
        $args->ProcessId = @res['ProcessId'];
        print '80% ... A iniciar operação ValidateOtp';
        print 'Introduza o OTP recebido no seu dispositivo: ';
        $opt = <STDIN>;
        # Removes new line from the input 
        chomp $opt; 
        $args->OPT = $opt;
        print '90% ... A contactar servidor SOAP CMD para operação ValidateOtp';
        @res = cmd_soap_msg::validate_otp($client, $args);
        if(@res['Status']['Code'] != '200'){
            die 'Erro @res[\'Status\'][\'Code\']. @res[\'Status\'][\'Message\']';
        }
        $decoded_res = decode_base64(encode_base64(res['Signature']));
        print '100% ... Assinatura (em base 64) devolvida pela operação ValidateOtp: $decoded_res';
        print '110% ... A validar assinatura ...';
        $digest = sha256($file_content);
        my $rsa_pub = Crypt::OpenSSL::RSA->new_public_key($decoded->pubkey);
        my $valid = $rsa_pub->do_verify($digest, @res['Signature']);
        assert($valid,'Signature Verification!');
        print 'Assinatura verificada com sucesso, baseada na assinatura recebida, na hash gerada e na chave pública do certificado de @certs_chain[\'user\']';
        return '\n+++ Test All finalizado +++\n'
    } else{
            die 'Impossível obter certificado'
        }
    return 'Erro ao iniciar teste!'
}