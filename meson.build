project('pam_wifi', 'cpp', version: '0.1.0', default_options: ['cpp_std=c++14'])

inih_cpp = dependency('INIReader', fallback: ['inih', 'INIReader_dep'])
libpam = meson.get_compiler('cpp').find_library('pam')

shared_library(
	'pam_wifi',
	'main.cpp',
	'process/process.cpp',
	'process/process_unix.cpp',
	dependencies: [
		libpam,
		inih_cpp,
	],
	install: true,
	install_dir: '/lib64/security',
	name_prefix: ''
)
