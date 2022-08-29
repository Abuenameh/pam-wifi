project('pam_wifi', 'cpp', version: '0.1.0', default_options: ['cpp_std=c++14'])

libpam = meson.get_compiler('cpp').find_library('pam')

shared_library(
	'pam_wifi',
	'main.cpp',
	dependencies: [
		libpam,
	]
)
