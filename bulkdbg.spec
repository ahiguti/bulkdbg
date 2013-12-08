Summary: bulkdbg
Name: bulkdbg
Version: 0.0.7
Release: 1%{?dist}
Group: System Environment/Libraries
License: BSD
Source: bulkdbg.tar.gz
Packager: Akira Higuchi <higuchi dot akira at dena dot jp>
BuildRoot: /var/tmp/%{name}-%{version}-root

%description

%prep
%setup -n %{name}

%define _use_internal_dependency_generator 0

%build
make

%install
rm -rf $RPM_BUILD_ROOT
mkdir -p $RPM_BUILD_ROOT/%{_bindir}
install -m 755 bulkdbg $RPM_BUILD_ROOT/%{_bindir}
install -m 755 bulkdbg_threads $RPM_BUILD_ROOT/%{_bindir}

%files
%defattr(-, root, root)
%{_bindir}/*

