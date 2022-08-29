project('wifi-auth', 'cpp', version: '0.1.0', default_options: ['cpp_std=c++14'])

inih_cpp = dependency('INIReader', fallback: ['inih', 'INIReader_dep'])

executable(
	'wifi-auth',
	'wifi_auth.cpp',
	'process/process.cpp',
	'process/process_unix.cpp',
	dependencies: [
		inih_cpp,
	]
)
