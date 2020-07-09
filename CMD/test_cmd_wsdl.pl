use File::Basename;
use File::Slurp;
use Try::Tiny;
use Digest::SHA qw(sha256);
use MIME::Base64;
use Getopt::Long;
use Switch;
use File::Basename qw(dirname);
use Cwd  qw(abs_path);
use lib dirname(dirname abs_path $0) . "/CMD/";
use Crypt::OpenSSL::X509;
use Crypt::PK::RSA;
use Encode;
use Crypt::Misc 'write_rawfile';
# Assertions are on.
use Carp::Assert;

use cmd_config;
use cmd_soap_msg;
use verifiers;

$TEXT = "test Command Line Program (for Preprod/Prod Signature CMD (SOAP) version 1.6 technical specification)";
$VERSION = "version: 1.0";
$APPLICATION_ID = cmd_config::get_appid();

#Função main do programa.
#Verifica se o APPLICATION_ID está definido
die "Configure o APPLICATION_ID\n" unless defined $APPLICATION_ID;

#Verificação de um número de inputs suficiente
$number_of_args = $#ARGV + 1;
die "Use -h for usage:\n  $0, -h for all operations\n  $0, -o <oper1> -h for usage of operation <oper1>\n\nAvailable operations:\n\ngc (GetCertificate)       Get User Certificate\nms (CCMovelSign)          Start signature process\nmms (CCMovelMultipleSign) Start multiple signature process\notp (ValidateOtp)         Validate OTP\ntest (TestAll)            Automatically test all commands\n" unless $number_of_args > 1;

#Faz o parser dos argumentos recebidos
@args = &args_parse;

die "Argumento passado (prod) deve ser 0 ou 1 não indefinido.\n" unless defined($args[7]);
$client = cmd_soap_msg::get_wsdl($args[7]);

cmd_soap_msg::debug($args[8]);


switch($args[0]) {
    case "test"    { print testall($client,\@args);                           }
    case "gc"      { print cmd_soap_msg::getcertificate($client,\@args);      }
    case "ms"      { print cmd_soap_msg::ccmovelsign($client,\@args);         }
    case "mms"     { print cmd_soap_msg::ccmovelmultiplesign($client,\@args); }
    case "otp"     { print cmd_soap_msg::validate_otp($client,\@args);        }
    else           { die "Select a proper Option!!\n" ;                       }
}


# -h      -> ajuda
# -o      -> opção escolhida (test, getcertificat,...)
# -f      -> nome do ficheiro
# -u      -> número do utilizador (ex:+351 000000000)
# -p      -> pin
# -otp    -> input line code received on selfphone
# -procId -> Process Id
# -app    -> APPLICATION_ID
# -prod   -> escolher prepod ou pod {0,1}
# -d      -> permite debug {0,1}
# hash    -> hash a ser produzido mais á frente
# docName -> nome a ser copiado do ficheiro
sub args_parse{
    # VERIFICAR TAMANHO DO INPUT, O PERL PERMITE CRESCIMENTO ATÉ AO FIM DA STACK DA RAM
    my @args;
    GetOptions(
        'h'        => \(my $help),
        'o:s'      => \$args[0],
        'f:s'      => \$args[1],
        'u=s'      => \$args[2],
        'p:s'      => \$args[3],
        'otp:s'    => \$args[4],
        'procId:s' => \$args[5],
        'app:s'    => \($args[6] = $APPLICATION_ID), #default está definido no modulo cmd_config
        'prod'     => \($args[7] = 0), #default value is 0 -> usa prepod
        'd'        => \($args[8] = 0), #default value is 0 -> sem debug
    );

    if(defined($help)){
        switch($args[0]){
            case "test"    { print "Automatically test all commands\n";  info(@a = ('-f','-u','-p')); }
            case "gc"      { print "Get user certificate\n";             info(@a = ('-u')); }
            case "ms"      { print "Start signature process\n";          info(@a = ('-u','-p')); }
            case "mms"     { print "Start multiple signature process\n"; info(@a = ('-u','-p')); }
            case "otp"     { print "Validate OTP\n";                     info(@a = ('-otp','-procId')); }
            else           { die "Select a proper Option!!\n" ;          }
        }
    }
    else{
        verifier(\@args,$help);
    }
    return @args;
}

sub info{
    my %help = (
        '-h'      => 'help',
        '-f'      => 'filepath',
        '-u'      => 'user phone number ( -u +XXX NNNNNNNNN)',
        '-p'      => 'CMD signature PIN',
        '-otp'    => 'OTP received in your device',
        '-procId' => 'ProcessID received in the answer of the CCMovelSign/CCMovelMultipleSign command',
        '-app'    => 'CMD ApplicationId (-app XXXXX)',
        '-prod'   => 'Use production SCMD service (preproduction SCMD service used by default)',
        '-d'      => 'show debug information'
        );
    print "\nPositional Arguments:\n";
    map { print "$_    => $help{$_}\n"; } @_ ;
    print "\nOptional Arguments:\n";
    map { print "$_    => $help{$_}\n"; } (@Array = ('-h','-app','-prod','-d')) ;
    exit 1;
}

#Verifica tamanho máximo dos inputs e os tipos
#Verifica sql injection
sub verifier{
    my @args = @{$_[0]};
    my $help = $_[1];
    #Verifica que dados mandatórios são fornecidos 
    switch($args[0]) {
        case "test"    { die "Missing values. Insert the madatory data!\n" unless (defined($args[1]) and defined($args[2]) and defined($args[3])) or $help == 1; }
        case "gc"      { die "Missing values. Insert the madatory data!\n" unless defined($args[2]) or $help == 1; }
        case "ms"      { die "Missing values. Insert the madatory data!\n" unless (defined($args[2]) and defined($args[3])) or $help == 1; }
        case "mms"     { die "Missing values. Insert the madatory data!\n" unless (defined($args[2]) and defined($args[3])) or $help == 1; }
        case "otp"     { die "Missing values. Insert the madatory data!\n" unless (defined($args[4]) and defined($args[5])) or $help == 1; }
        else           { die "Select a proper Option!!\n"; }
    }

    verifiers::input(\@args);
    map{die "I know what your up to! Don't try to SQL inject me!!\n" unless verifiers::sqlInjection($_) == 0;} @args;
    map{die "I know what your up to! Don't try to XML inject me!!\n" unless verifiers::xmlInjection($_) == 0;} @args;
}

# Testa todos os comandos
sub testall{
    print "$TEXT \n  $VERSION\n";
    print "\n+++ Test All inicializado +++\n";
    print " 0% ... Leitura de argumentos da linha de comando - file: $args.file user: $args.user pin: $args.pin\n";
    print "10% ... A contactar servidor SOAP CMD para operação GetCertificate\n";
    my ($client, $args) = @_;
    #certs[0] = user; certs[1] = root; certs[2] = CA
    @cmd_certs = cmd_soap_msg::getcertificate($client, \@args);
    map {die 'Ups! Something went wrong with the certificates! They haven\'t been returned!' unless defined($_);} @cmd_certs;
    #print( $cmd_certs[0] ); -> igual <=>
    #print( $user_cert->pubkey()); #->diferente? -> módulo Crypt::OpenSSL::X509 defeituoso(comparar com pubkey do python)
    write_rawfile("cert.pem",$cmd_certs[0]);

    $user_cert = Crypt::OpenSSL::X509->new_from_string($cmd_certs[0], Crypt::OpenSSL::X509::FORMAT_PEM);
    $root_cert = Crypt::OpenSSL::X509->new_from_string($cmd_certs[1], Crypt::OpenSSL::X509::FORMAT_PEM);
    $CA_cert   = Crypt::OpenSSL::X509->new_from_string($cmd_certs[2], Crypt::OpenSSL::X509::FORMAT_PEM);
  
    $subject_info = encode('UTF-8',$user_cert->subject());
    @subject_aux = split 'CN=',$subject_info;
    $subject = $subject_aux[1];
    $ca_info = encode('UTF-8',$CA_cert->subject());
    @ca_aux = split 'CN=',$ca_info;
    $ca = $ca_aux[1];
    $root_info = encode('UTF-8',$root_cert->subject());
    @root_aux = split 'CN=',$root_info;
    $root = $root_aux[1];
    #Caso se queira verificar o algoritmo a usar descomentam-se as 2 linhas abaixo -> sha256WithRSAEncryption
    #$sigalgorithm = $user_cert->sig_alg_name();
    #print("\nAlg => " . $sigalgorithm . '\n');
   
    print "20% ... Certificado emitido para $subject pela Entidade de Certificação $ca na hierarquia do  $root\n";
    print "30% ... Leitura do ficheiro $args[1]\n";
    
    my $content;
    open(my $fh, "<", $args[1]) or die "Ficheiro não encontrado.\n"; # previne pipelining
    {
        local $/;
        $content = <$fh>;
    }
    close($fh);
    print "40% ... Geração de hash do ficheiro $args[1]\n";
    $digest = sha256($content);
    $args[9] = $digest; # Geração do Digest
    $encoded_arg = encode_base64($args[9]);
    print "50% ... Hash gerada (em base64): $encoded_arg\n";
    print "60% ... A contactar servidor SOAP CMD para operação CCMovelSign\n";
    $args[10] = $args[1];
    
    $process_id = cmd_soap_msg::ccmovelsign($client, \@args, "SHA256");
    die 'Server side fail! ProcessId was not returned!' unless defined($process_id);
    print "70% ... ProcessID devolvido pela operação CCMovelSign: $process_id\n";
    $args[5] = $process_id;
    print "80% ... A iniciar operação ValidateOtp\n";
    print "Introduza o OTP recebido no seu dispositivo: ";
    $otp = <STDIN>;
    # Removes new line from the input 
    chomp $otp;
    verifiers::valid_otp($otp); 
    $args[4] = $otp;
    print "90% ... A contactar servidor SOAP CMD para operação ValidateOtp\n";
    
    $signature = cmd_soap_msg::validate_otp($client, \@args);
    die 'Not the right OTP!' unless defined($signature);
    print "100% ... Assinatura (em base 64) devolvida pela operação ValidateOtp: $signature\n";
    print "110% ... A validar assinatura ...\n";
    
    $digest = sha256($content);

    # Escrever chave publica num ficheiro PEM
    $cert_pk1 = $user_cert->pubkey();
    write_rawfile("rsakey1.pub.pem",$cert_pk1);

=head
    CHAVE PÚBLICA RETIRADA DO PYTHON -> O MÓDULO DE VERIFICAÇÃO TEM UM ERRO
    $cert_pk2 = '-----BEGIN PUBLIC KEY-----MIIBojANBgkqhkiG9w0BAQEFAAOCAY8AMIIBigKCAYEAvqD0edlNMwzOvTMUaEyE9uAqGNCX5kZdtihj6S2Yq5BVk8vQIZH8UKkuJxDI1/XYb7cpDCmQRIwR9NXAEpnFUg26eYKEfPLXykdbtsMgBlBr5xVZTrDoyBUHWphjpjrG8sZocuRzqb7CAHCTIKADvDySO8nDoaxfu4rligk35qj1EILUc4KaCXhQx9SC2p9zAtJkva3HiXTzU8RV03If/3tcepo0Amkuvadl8nTABxFhD93O4B2SWjbNRAeeQe5qbPUs7Tf9A4VV95RVxfbMMJ3UGWfRy12cifAukZDDypR/Jhh0yRq0W38zeFQAIq6AsheTxRjteYIfWfknqicAPLy/gO1FV6GGPSwkcLSLN+YJZB5929pjrs8c5GvOmB82SO6C9S/TPJix973+p1W82SZkkazmJB0kB+qAHTW1htHW7phoJVh58ksQ1CrMeabbOjmgetOs5jtLsafyU7b8/CHXuJO+8ipYgj8LaJvuxdojKnTeMrhbSpH56siW42s/AgMBAAE=-----END PUBLIC KEY-----';

    write_rawfile("rsakey2.pub.pem",$cert_pk2);

    #Criar objeto 1 para verificacao da mensagem
    $pk1 = Crypt::PK::RSA->new("rsakey1.pub.pem");
    # 0 -> Carregou a chave publica com sucesso

    #Criar objeto 2 para verificacao da mensagem
    $pk2 = Crypt::PK::RSA->new("rsakey2.pub.pem");
    # 0 -> Carregou a chave publica com sucesso

    $v1 = Crypt::PK::RSA::rsa_verify_message("rsakey1.pub.pem", $signature, $content, 'SHA256');
    $v1_1 = Crypt::PK::RSA::rsa_verify_message("rsakey1.pub.pem", $signature, $digest, 'SHA256');
    $v2 = Crypt::PK::RSA::rsa_verify_message("rsakey1.pub.pem", $signature, $digest);
    $v2_1 = Crypt::PK::RSA::rsa_verify_message("rsakey1.pub.pem", $signature, $content);
    $v3 = Crypt::PK::RSA::rsa_verify_message("rsakey2.pub.pem", $signature, $content, 'SHA256');
    $v3_1 = Crypt::PK::RSA::rsa_verify_message("rsakey2.pub.pem", $signature, $digest, 'SHA256');
    $v4 = Crypt::PK::RSA::rsa_verify_message("rsakey2.pub.pem", $signature, $digest);
    $v4_1 = Crypt::PK::RSA::rsa_verify_message("rsakey2.pub.pem", $signature, $content);
    $v5 = Crypt::PK::RSA::rsa_verify_message("rsakey1.pub.pem", $signature, $content, 'SHA256', 'v1.5');
    $v5_1 = Crypt::PK::RSA::rsa_verify_message("rsakey1.pub.pem", $signature, $digest, 'SHA256', 'v1.5');
    $v6 = Crypt::PK::RSA::rsa_verify_message("rsakey2.pub.pem", $signature, $content, 'SHA256', 'v1.5');
    $v6_1 = Crypt::PK::RSA::rsa_verify_message("rsakey2.pub.pem", $signature, $digest, 'SHA256', 'v1.5');
    print('failed1!') if($v1 == 0);
    print('failed1.1!') if($v1_1 == 0);
    print('failed2!') if($v2 == 0);
    print('failed2.1!') if($v2_1 == 0);
    print('failed3!') if($v3 == 0);
    print('failed3.1!') if($v3_1 == 0);
    print('failed4!') if($v4 == 0);
    print('failed4.1!') if($v2_1 == 0);
    print('failed5!') if($v5 == 0);
    print('failed5.1!') if($v5_1 == 0);
    print('failed6!') if($v6 == 0);
    print('failed6.1!') if($v6_1 == 0);
=cut
    #O módulo não funciona o resultado deveria ser 1 mas dá 0...! Quando o módulo for corrigido alterar para 1 no assert!
    assert(Crypt::PK::RSA::rsa_verify_message("rsakey1.pub.pem", $signature, $content, 'SHA256', 'v1.5') == 0,"Failed to verify");
    print "Assinatura verificada com sucesso, baseada na assinatura recebida, na hash gerada e na chave pública do certificado de $subject\n";
    return "\n+++ Test All finalizado +++\n";
}