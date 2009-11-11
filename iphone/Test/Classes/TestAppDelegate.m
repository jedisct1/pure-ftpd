//
//  TestAppDelegate.m
//  Test
//
//  Created by Frank Denis on 29/10/09.
//  Copyright __MyCompanyName__ 2009. All rights reserved.
//

#import "TestAppDelegate.h"
#import "TestViewController.h"

@implementation TestAppDelegate

@synthesize window;
@synthesize viewController;
@synthesize ftpService;
@synthesize ftpOn;

extern void pureftpd_register_login_callback(void (*callback)(void *user_data), void *user_data);
extern void pureftpd_register_logout_callback(void (*callback)(void *user_data), void *user_data);
extern void pureftpd_register_log_callback(void (*callback)(int crit, const char *message, void *user_data), void *user_data);
extern int  pureftpd_start(int argc, char *argv[], const char *baseDir);
extern int  pureftpd_shutdown(void);
extern int  pureftpd_enable(void);
extern int  pureftpd_disable(void);

// 0: The switch totally shuts the server down
// 1: The switch accepts / refuses new connections without shutting the server down
#define kSUSPEND_INSTEAD_OF_SHUTDOWN 0

static NSString *baseDir;

- (void) getBaseDir {
	baseDir = nil;
	NSFileManager *fileManager = [NSFileManager defaultManager];
	NSArray *dirs = NSSearchPathForDirectoriesInDomains(NSDocumentDirectory, NSUserDomainMask, YES);
	NSDictionary *attrs;
	for (NSString *dir in dirs) {
		attrs = [fileManager attributesOfItemAtPath: dir error: NULL];
		if (attrs == nil) {
			NSLog(@"[%@] is not an option", dir);
			continue;
		}
		NSString *fileType = [attrs fileType];
		if (![fileType isEqualToString: @"NSFileTypeDirectory"]) {
			NSLog(@"[%@] is not a directory", dir);
			continue;			
		}
		if ([fileManager isWritableFileAtPath: dir] != TRUE) {
			NSLog(@"[%@] isn't a writeable directory", dir);
			continue;						
		}
		baseDir = dir;
		break;
	}
	[baseDir retain];
}

void ftpLoginCallback(void *userData) {
	NSLog(@"A client just logged in");
}

void ftpLogoutCallback(void *userData) {
	NSLog(@"A client just logged out");
}

void ftpLogCallback(int crit, const char *message, void *userData) {
	NSLog(@"LOG(%d) [%s]", crit, message);
}

- (void) ftpthread: (id) fodder {
	[[NSAutoreleasePool alloc] init];
	char *args[] = {
		"pure-ftpd", "--anonymouscancreatedirs", "--dontresolve", "--allowdotfiles", "--customerproof",
		NULL
	};
	pureftpd_register_login_callback(ftpLoginCallback, self);
	pureftpd_register_logout_callback(ftpLogoutCallback, self);
	pureftpd_register_log_callback(ftpLogCallback, self);
	NSLog(@"Server started");
	for (;;) {		
		pureftpd_start((int) (sizeof args / sizeof *args) - 1, args, [baseDir UTF8String]);
		if (ftpOn == FALSE) {
			break;
		}
		NSLog(@"Server immediately restarted");		
	}
	NSLog(@"Server stopped");
}

- (void) ftpStart {
	NSLog(@"Turning FTP server ON...");
	ftpOn = TRUE;
	[viewController showFtpActivity: TRUE];	
	[ftpService publish];
	[NSThread detachNewThreadSelector: @selector(ftpthread:) toTarget:self withObject:nil];
}

- (void) ftpStop {
	NSLog(@"Turning FTP server OFF");	
	ftpOn = FALSE;
	[viewController showFtpActivity: FALSE];
	[ftpService stop];
	pureftpd_shutdown();	
}

- (void) ftpEnable {
	NSLog(@"Accepting client connections");
	[viewController showFtpActivity: TRUE];
	[ftpService publish];
	pureftpd_enable();
}

- (void) ftpDisable {
	NSLog(@"Refusing client connections");
	[viewController showFtpActivity: FALSE];
	[ftpService stop];
	pureftpd_disable();
}

- (void) ftpOnOffStatusChanged: (NSNotification *) notification {
	const BOOL on = [(NSNumber *) [notification.userInfo objectForKey: @"on"] boolValue];
#if kSUSPEND_INSTEAD_OF_SHUTDOWN
	if (on) {
		[self ftpEnable];
	} else {
		[self ftpDisable];
	}	
#else
	if (on) {
		[self ftpStart];
	} else {
		[self ftpStop];
	}
#endif
}

- (void) applicationDidFinishLaunching:(UIApplication *)application {   
	[self getBaseDir];
	ftpService = [[NSNetService alloc] initWithDomain:@"" type:@"_ftp._tcp" name:@"iPhone FTP Server" port: 2121];
	[[NSNotificationCenter defaultCenter] addObserver: self selector: @selector(ftpOnOffStatusChanged:) name: @"ftp_on_off_status_changed" object: nil];
	
	[window addSubview:viewController.view];
	[window makeKeyAndVisible];
	
	[self ftpStart];
}

- (void) dealloc {
	[ftpService stop];
	[ftpService release];
    [viewController release];
    [window release];
    [super dealloc];
}

@end
