Summary: bulkdbg
Name: bulkdbg
Version: 0.0.23
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
mkdir -p $RPM_BUILD_ROOT/%{_includedir}
mkdir -p $RPM_BUILD_ROOT/%{_libdir}
install -m 755 bulkdbg $RPM_BUILD_ROOT/%{_bindir}
install -m 644 bulkdbg.h $RPM_BUILD_ROOT/%{_includedir}
install -m 644 libbulkdbg.a $RPM_BUILD_ROOT/%{_libdir}

%files
%defattr(-, root, root)
%{_includedir}/*
%{_bindir}/*
%{_libdir}/*

