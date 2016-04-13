#!/usr/bin/perl

# Спасибо Павлу Одинцову, за большую проделанную работу =)

use strict;
use warnings;

use Getopt::Long;

my $temp_folder_for_building_project = `mktemp -d /tmp/synflood.build.dir.XXXXXXXXXX`;
chomp $temp_folder_for_building_project;

unless ($temp_folder_for_building_project && -e $temp_folder_for_building_project) {
    die "Can't create temp folder in /tmp for building project: $temp_folder_for_building_project\n";
}

my $start_time = time();
my $install_log_path = '/tmp/synflood_install.log';

my $os_type = '';
my $distro_type = '';
my $distro_version = '';
my $distro_architecture = '';

# Used for VyOS and different appliances based on rpm/deb
my $appliance_name = '';

# So, you could disable this option but without this feature we could not improve FastNetMon for your distribution
my $do_not_track_me = '';

my $cpus_number = 1;

# We could pass options to make with this variable
my $make_options = '';

# We could pass options to configure with this variable
my $configure_options = '';

# We will build gcc, stdc++ and boost for this distribution from sources
my $build_binary_environment = '';

# Get options from command line
GetOptions(
    'do-not-track-me' => \$do_not_track_me,
    'build-binary-environment' => \$build_binary_environment,
);

my $we_have_log4cpp_support = '';

main();

sub get_logical_cpus_number {
    if ($os_type eq 'linux') {
        my @cpuinfo = `cat /proc/cpuinfo`;
        chomp @cpuinfo;

        my $cpus_number = scalar grep {/processor/} @cpuinfo;

        return $cpus_number;
    } elsif ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        my $cpus_number = `sysctl -n hw.ncpu`;
        chomp $cpus_number;
    }
}

### Functions start here
sub main {
    detect_distribution();
    $cpus_number = get_logical_cpus_number();

    # We could get huge speed benefits with this option
    if ($cpus_number > 1) {
        print "You have really nice server with $cpus_number CPU's and we will use they all for build process :)\n";
        $make_options = "-j $cpus_number";
    }

    # Refresh information about packages
    init_package_manager();

    install_gcc();
    install_boost_builder();
    install_boost();
    install_json_c();
    install_log4cpp();


    my $install_time = time() - $start_time;
    my $pretty_install_time_in_minutes = sprintf("%.2f", $install_time / 60);

    print "We have built project in $pretty_install_time_in_minutes minutes\n";
}

sub exec_command {
    my $command = shift;

    open my $fl, ">>", $install_log_path;
    print {$fl} "We are calling command: $command\n\n";

    my $output = `$command 2>&1 >> $install_log_path`;

    print {$fl} "Command finished with code $?\n\n";

    if ($? == 0) {
        return 1;
    } else {
        return '';
    }
}

sub get_sha1_sum {
    my $path = shift;

    if ($os_type eq 'freebsd') {
        # # We should not use 'use' here because we haven't this package on non FreeBSD systems by default
        require Digest::SHA;

        # SHA1
        my $sha = Digest::SHA->new(1);

        $sha->addfile($path);

        return $sha->hexdigest;
    }

    my $hasher_name = '';

    if ($os_type eq 'macosx') {
        $hasher_name = 'shasum';
    } elsif ($os_type eq 'freebsd') {
        $hasher_name = 'sha1';
    } else {
        # Linux
        $hasher_name = 'sha1sum';
    }

    my $output = `$hasher_name $path`;
    chomp $output;

    my ($sha1) = ($output =~ m/^(\w+)\s+/);

    return $sha1;
}

sub download_file {
    my ($url, $path, $expected_sha1_checksumm) = @_;

    `wget --no-check-certificate --quiet '$url' -O$path`;

    if ($? != 0) {
        print "We can't download archive $url correctly\n";
        return '';
    }

    if ($expected_sha1_checksumm) {
        my $calculated_checksumm = get_sha1_sum($path);

        if ($calculated_checksumm eq $expected_sha1_checksumm) {
            return 1;
        } else {
            print "Downloaded archive has incorrect sha1: $calculated_checksumm expected: $expected_sha1_checksumm\n";
            return '';
        }
    } else {
        return 1;
    }
}

sub install_gcc {
    # Add new compiler to configure options
    # It's mandatory for log4cpp
    $configure_options = "CC=/opt/gcc520/bin/gcc CXX=/opt/gcc520/bin/g++";

    # More detailes about jam lookup: http://www.boost.org/build/doc/html/bbv2/overview/configuration.html

    # We use non standard gcc compiler for Boost builder and Boost and specify it this way
    open my $fl, ">", "/root/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$fl} "using gcc : 5.2 : /opt/gcc520/bin/g++ ;\n";
    close $fl;

    # When we run it with vzctl exec we ahve broken env and should put config in /etc too
    open my $etcfl, ">", "/etc/user-config.jam" or die "Can't open $! file for writing manifest\n";
    print {$etcfl} "using gcc : 5.2 : /opt/gcc520/bin/g++ ;\n";
    close $etcfl;

    # Install gcc from sources
    if ($distro_type eq 'debian') {
        my @dependency_list = ('libmpfr-dev', 'libmpc-dev');

        if ($distro_version <= 7) {
            # We have another name for Debian 6 Squeeze
            push @dependency_list, 'libgmp3-dev';
        } else {
            push @dependency_list, 'libgmp-dev';
        }

        apt_get(@dependency_list);
    } elsif ($distro_type eq 'ubuntu') {
        my @dependency_list = ('libmpfr-dev', 'libmpc-dev', 'libgmp-dev');

        apt_get(@dependency_list);
    } elsif ($distro_type eq 'centos') {
        if ($distro_version == 6) {
            # We haven't libmpc in base repository here and should enable EPEL
            yum('https://dl.fedoraproject.org/pub/epel/epel-release-latest-6.noarch.rpm');
        }

        my @dependency_list = ('gmp-devel', 'mpfr-devel', 'libmpc-devel');

        yum(@dependency_list);
    }

    print "Download gcc archive\n";
    chdir $temp_folder_for_building_project;

    my $archive_file_name = 'gcc-5.2.0.tar.gz';
    my $gcc_download_result = download_file("ftp://ftp.mpi-sb.mpg.de/pub/gnu/mirror/gcc.gnu.org/pub/gcc/releases/gcc-5.2.0/$archive_file_name", $archive_file_name, '713211883406b3839bdba4a22e7111a0cff5d09b');

    unless ($gcc_download_result) {
        die "Can't download gcc sources\n";
    }

    print "Unpack archive\n";
    exec_command("tar -xf $archive_file_name");
    exec_command("mkdir $temp_folder_for_building_project/gcc-5.2.0-objdir");

    chdir "$temp_folder_for_building_project/gcc-5.2.0-objdir";

    print "Configure build system\n";
    exec_command("$temp_folder_for_building_project/gcc-5.2.0/configure --prefix=/opt/gcc520 --enable-languages=c,c++ --disable-multilib");

    print "Build gcc\n";
    exec_command("make $make_options");
    exec_command("make $make_options install");

    # We do not add it to ld.so.conf.d path because it could broke system
}

sub install_boost {
    chdir '/opt';
    my $archive_file_name = 'boost_1_58_0.tar.gz';

    print "Install Boost dependencies\n";

    # libicu dependencies
    if ($distro_type eq 'ubuntu') {

        if ($distro_version eq '14.04') {
            apt_get('libicu52');
        }

        if ($distro_version eq '12.04') {
            apt_get('libicu48');
        }
    }

    print "Download Boost source code\n";
    my $boost_download_result = download_file("http://downloads.sourceforge.net/project/boost/boost/1.58.0/boost_1_58_0.tar.gz?r=http%3A%2F%2Fwww.boost.org%2Fusers%2Fhistory%2Fversion_1_58_0.html&ts=1439207367&use_mirror=cznic", $archive_file_name, 'a27b010b9d5de0c07df9dddc9c336767725b1e6b');

    unless ($boost_download_result) {
        die "Can't download Boost source code\n";
    }

    print "Unpack Boost source code\n";
    exec_command("tar -xf $archive_file_name");

    # Remove archive
    unlink "$archive_file_name";

    chdir "boost_1_58_0";

    print "Build Boost\n";
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path
    # So without HOME=/root nothing worked correctly due to another "openvz" feature
    my $b2_build_result = exec_command("HOME=/root PATH=\$PATH:/opt/gcc520/bin /opt/boost_build1.5.8/bin/b2 -j$cpus_number --build-dir=/tmp/boost_build_temp_directory_1_5_8 toolset=gcc-5.2 link=shared --without-test --without-python --without-wave --without-graph --without-coroutine --without-math --without-log --without-graph_parallel --without-mpi");

    # We should not do this check because b2 build return bad return code even in success case... when it can't build few non important targets
    unless ($b2_build_result) {
        ### die "Can't execute b2 build correctly\n";
    }
}

sub install_boost_builder {
    chdir $temp_folder_for_building_project;

    # We need libc headers for compilation of this code
    if ($distro_type eq 'centos') {
        yum('glibc-devel');
    }

    # We use another name because it uses same name as boost distribution
    my $archive_file_name = 'boost-builder-1.58.0.tar.gz';

    print "Download boost builder\n";
    my $boost_build_result = download_file("https://github.com/boostorg/build/archive/boost-1.58.0.tar.gz", $archive_file_name,
        'e86375ed83ed07a79a33c76e80e8648d969b3218');

    unless ($boost_build_result) {
        die "Can't download boost builder\n";
    }

    print "Unpack boost builder\n";
    exec_command("tar -xf $archive_file_name");

    chdir "build-boost-1.58.0";

    print "Build Boost builder\n";
    # We haven't system compiler here and we will use custom gcc for compilation here
    my $bootstrap_result = exec_command("CC=/opt/gcc520/bin/gcc CXX=/opt/gcc520/bin/g++ ./bootstrap.sh --with-toolset=cc");

    unless ($bootstrap_result) {
        die "bootstrap of Boost Builder failed, please check logs\n";
    }

    # We should specify toolset here if we want to do build with custom compiler
    # We have troubles when run this code with vzctl exec so we should add custom compiler in path
    my $b2_install_result = exec_command("PATH=\$PATH:/opt/gcc520/bin ./b2 install --prefix=/opt/boost_build1.5.8 toolset=gcc");

    unless ($b2_install_result) {
        die "Can't execute b2 install\n";
    }
}

sub install_log4cpp {

    my $distro_file_name = 'log4cpp-1.1.1.tar.gz';
    my $log4cpp_url = 'https://sourceforge.net/projects/log4cpp/files/log4cpp-1.1.x%20%28new%29/log4cpp-1.1/log4cpp-1.1.1.tar.gz/download';
    my $log4cpp_install_path = '/opt/log4cpp1.1.1';

    chdir $temp_folder_for_building_project;

    print "Download log4cpp sources\n";
    my $log4cpp_download_result = download_file($log4cpp_url, $distro_file_name, '23aa5bd7d6f79992c92bad3e1c6d64a34f8fcf68');

    unless ($log4cpp_download_result) {
        die "Can't download log4cpp\n";
    }

    print "Unpack log4cpp sources\n";
    exec_command("tar -xf $distro_file_name");
    chdir "$temp_folder_for_building_project/log4cpp";

    print "Build log4cpp\n";

    # TODO: we need some more reliable way to specify options here
    if ($configure_options) {
        exec_command("$configure_options ./configure --prefix=$log4cpp_install_path");
    } else {
        exec_command("./configure --prefix=$log4cpp_install_path");
    }

    exec_command("make $make_options install");

    print "Add log4cpp to ld.so.conf\n";
    put_library_path_to_ld_so("/etc/ld.so.conf.d/log4cpp.conf", "$log4cpp_install_path/lib");
}

sub init_package_manager {

    print "Update package manager cache\n";
    if ($distro_type eq 'debian' or $distro_type eq 'ubuntu') {
        exec_command("apt-get update");
    }

    if ($os_type eq 'freebsd') {
        exec_command("pkg update");
    }
}

sub put_library_path_to_ld_so {
    my ($ld_so_file_path, $library_path) = @_;

    if ($os_type eq 'macosx' or $os_type eq 'freebsd') {
        return;
    }

    open my $ld_so_conf_handle, ">", $ld_so_file_path or die "Can't open file $ld_so_file_path $! for writing\n";
    print {$ld_so_conf_handle} $library_path;
    close $ld_so_conf_handle;

    exec_command("ldconfig");
}

sub read_file {
    my $file_name = shift;

    my $res = open my $fl, "<", $file_name;

    unless ($res) {
        return "";
    }

    my $content = join '', <$fl>;
    chomp $content;

    return $content;
}

# Detect operating system of this machine
sub detect_distribution {
    # We use following global variables here:
    # $os_type, $distro_type, $distro_version, $appliance_name

    my $uname_s_output = `uname -s`;
    chomp $uname_s_output;

    # uname -a output examples:
    # FreeBSD  10.1-STABLE FreeBSD 10.1-STABLE #0 r278618: Thu Feb 12 13:55:09 UTC 2015     root@:/usr/obj/usr/src/sys/KERNELWITHNETMAP  amd64
    # Darwin MacBook-Pro-Pavel.local 14.5.0 Darwin Kernel Version 14.5.0: Wed Jul 29 02:26:53 PDT 2015; root:xnu-2782.40.9~1/RELEASE_X86_64 x86_64
    # Linux ubuntu 3.16.0-30-generic #40~14.04.1-Ubuntu SMP Thu Jan 15 17:43:14 UTC 2015 x86_64 x86_64 x86_64 GNU/Linux

    if ($uname_s_output =~ /FreeBSD/) {
        $os_type = 'freebsd';
    } elsif ($uname_s_output =~ /Darwin/) {
        $os_type = 'macosx';
    } elsif ($uname_s_output =~ /Linux/) {
        $os_type = 'linux';
    } else {
        warn "Can't detect platform operating system\n";
    }

    if ($os_type eq 'linux') {
        # x86_64 or i686
        $distro_architecture = `uname -m`;
        chomp $distro_architecture;

        if (-e "/etc/debian_version") {
            # Well, on this step it could be Ubuntu or Debian

            # We need check issue for more details
            my @issue = `cat /etc/issue`;
            chomp @issue;

            my $issue_first_line = $issue[0];

            # Possible /etc/issue contents:
            # Debian GNU/Linux 8 \n \l
            # Ubuntu 14.04.2 LTS \n \l
            # Welcome to VyOS - \n \l
            my $is_proxmox = '';

            # Really hard to detect https://github.com/proxmox/pve-manager/blob/master/bin/pvebanner
            for my $issue_line (@issue) {
                if ($issue_line =~ m/Welcome to the Proxmox Virtual Environment/) {
                    $is_proxmox = 1;
                    $appliance_name = 'proxmox';
                    last;
                }
            }

            if ($issue_first_line =~ m/Debian/ or $is_proxmox) {
                $distro_type = 'debian';

                $distro_version = `cat /etc/debian_version`;
                chomp $distro_version;

                # Debian 6 example: 6.0.10
                # We will try transform it to decimal number
                if ($distro_version =~ /^(\d+\.\d+)\.\d+$/) {
                    $distro_version = $1;
                }
            } elsif ($issue_first_line =~ m/Ubuntu (\d+(?:\.\d+)?)/) {
                $distro_type = 'ubuntu';
                $distro_version = $1;
            } elsif ($issue_first_line =~ m/VyOS/) {
                # Yes, VyOS is a Debian
                $distro_type = 'debian';
                $appliance_name = 'vyos';

                my $vyos_distro_version = `cat /etc/debian_version`;
                chomp $vyos_distro_version;

                # VyOS have strange version and we should fix it
                if ($vyos_distro_version =~ /^(\d+)\.\d+\.\d+$/) {
                    $distro_version = $1;
                }
            }
        }

        if (-e "/etc/redhat-release") {
            $distro_type = 'centos';

            my $distro_version_raw = `cat /etc/redhat-release`;
            chomp $distro_version_raw;

            # CentOS 6:
            # CentOS release 6.6 (Final)
            # CentOS 7:
            # CentOS Linux release 7.0.1406 (Core)
            # Fedora release 21 (Twenty One)
            if ($distro_version_raw =~ /(\d+)/) {
                $distro_version = $1;
            }
        }

        if (-e "/etc/gentoo-release") {
            $distro_type = 'gentoo';

            my $distro_version_raw = `cat /etc/gentoo-release`;
            chomp $distro_version_raw;
        }

        unless ($distro_type) {
            die "This distro is unsupported, please do manual install";
        }

        print "We detected your OS as $distro_type Linux $distro_version\n";
    } elsif ($os_type eq 'macosx') {
        my $mac_os_versions_raw = `sw_vers -productVersion`;
        chomp $mac_os_versions_raw;

        if ($mac_os_versions_raw =~ /(\d+\.\d+)/) {
            $distro_version = $1;
        }

        print "We detected your OS as Mac OS X $distro_version\n";
    } elsif ($os_type eq 'freebsd') {
        my $freebsd_os_version_raw = `uname -r`;
        chomp $freebsd_os_version_raw;

        if ($freebsd_os_version_raw =~ /^(\d+)\.?/) {
            $distro_version = $1;
        }

        print "We detected your OS as FreeBSD $distro_version\n";
    }
}


sub apt_get {
    my @packages_list = @_;

    # We install one package per apt-get call because installing multiple packages in one time could fail of one package is broken
    for my $package (@packages_list) {
        exec_command("apt-get install -y --force-yes $package");

        if ($? != 0) {
            print "Package '$package' install failed with code $?\n"
        }
    }
}

sub yum {
    my @packages_list = @_;

    for my $package (@packages_list) {
        exec_command("yum install -y $package");

        if ($? != 0) {
            print "Package '$package' install failed with code $?\n";
        }
    }
}

sub get_active_network_interfaces {
    my @interfaces = `LANG=C netstat -i|egrep -v 'lo|Iface|Kernel'|awk '{print \$1}'`;
    chomp @interfaces;

    my @clean_interfaces = ();

    for my $iface (@interfaces) {
        # skip aliases
        if ($iface =~ /:/) {
            next;
        }

        push @clean_interfaces, $iface;
    }

    return  @clean_interfaces;
}

