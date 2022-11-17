%global pkg kp_oom
%global kernel_version 3.10.0-1160.71.1.el7
%global git_commit fb38ad15c659667b54d71ba3d3a769b841d08d75
%global modules_path /lib/modules/%{kernel_version}.%{_arch}/extra

%global debug_package %{nil}
%global __spec_install_post \
  %{?__debug_package:%{__debug_install_post}} \
  %{__arch_install_post} \
  %{__os_install_post} \
  %{__mod_compress_install_post}
%global __mod_compress_install_post find %{buildroot}/lib/modules -type f -name \*.ko -exec xz \{\} \\;

Name:             kmod-%{pkg}
Version:          1.1
Release:          1%{?dist}
Summary:          Singularity/EL7 OoM bug work-around
License:          kp_oom
URL:              https://github.com/pja237/%{pkg}
Source0:          https://github.com/pja237/%{pkg}/archive/%{git_commit}.tar.gz
ExclusiveArch:    x86_64
BuildRequires:    elfutils-libelf-devel
BuildRequires:    gcc
BuildRequires:    kmod
BuildRequires:    make
BuildRequires:    redhat-rpm-config
BuildRequires:    xz
BuildRequires:    kernel-abi-whitelists = %{kernel_version}
BuildRequires:    kernel-devel = %{kernel_version}
BuildRequires:    kernel-devel-uname-r = %{kernel_version}.%{_arch}
Requires:         kernel >= %{kernel_version}
Requires:         kernel-uname-r >= %{kernel_version}.%{_arch}
Provides:         installonlypkg(kernel-module)
Provides:         kernel-modules >= %{kernel_version}.%{_arch}
Requires(post):   %{_sbindir}/depmod
Requires(postun): %{_sbindir}/depmod
Requires(post):   %{_sbindir}/weak-modules
Requires(postun): %{_sbindir}/weak-modules

%description
An "unorthodox" fix for https://github.com/apptainer/singularity/issues/5850.

%prep
%autosetup -n %{pkg}-%{git_commit}

%build
%{__make} -C /usr/src/kernels/%{kernel_version}.%{_arch} %{?_smp_mflags} M=$PWD modules

%install
%{__install} -D %{pkg}.ko %{buildroot}/%{modules_path}/%{pkg}.ko
# Make .ko objects temporarily executable for automatic stripping
find %{buildroot}/lib/modules -type f -name \*.ko -exec chmod u+x \{\} \+

%clean
%{__rm} -rf %{buildroot}

%post
printf '%s\n' "%{modules_path}/%{pkg}.ko.xz" | %{_sbindir}/weak-modules --add-modules

%postun
printf '%s\n' "%{modules_path}/%{pkg}.ko.xz" | %{_sbindir}/weak-modules --remove-modules

%files
%defattr(644,root,root,755)
/lib/modules/%{kernel_version}.%{_arch}
%doc README.md

%changelog
* Thu Apr 21 2022 Laura Hild <lsh@jlab.org> - 1.1-1
- Initial RPM config, based on specfiles from CentOS' Kmods SIG.
