//
//  TestViewController.m
//  Test
//
//  Created by Frank Denis on 29/10/09.
//  Copyright __MyCompanyName__ 2009. All rights reserved.
//

#import "TestViewController.h"
#include <ifaddrs.h>
#include <arpa/inet.h>

@implementation TestViewController

@synthesize ipLabel;
@synthesize spinner;

- (NSString *)getIPAddress {
	NSString *address = @"error";
	struct ifaddrs *interfaces = NULL;
	struct ifaddrs *temp_addr = NULL;
	int success = 0;
	
	success = getifaddrs(&interfaces);
	if (success == 0) {
		temp_addr = interfaces;
		while(temp_addr != NULL) {
			if(temp_addr->ifa_addr->sa_family == AF_INET && strcmp(temp_addr->ifa_name, "en0") == 0) {
				address = [NSString stringWithUTF8String:inet_ntoa(((struct sockaddr_in *)temp_addr->ifa_addr)->sin_addr)];
			}
			temp_addr = temp_addr->ifa_next;
		}
	}	
	freeifaddrs(interfaces);
	
	return address;
}

- (void) onoffSwitchMoved: (id) sender {
	UISwitch *uiSwitch = (UISwitch *) sender;
	NSNumber *nsOn = [[NSNumber alloc] initWithBool: uiSwitch.on];
	NSDictionary *userInfo = [[NSDictionary alloc] initWithObjectsAndKeys: nsOn, @"on", nil];
	[nsOn release];
	NSNotification *notification = [NSNotification notificationWithName: @"ftp_on_off_status_changed" object: self userInfo: userInfo];
	[userInfo release];
	[[NSNotificationQueue defaultQueue] enqueueNotification: notification postingStyle: NSPostWhenIdle];
}

- (void)viewDidLoad {
    [super viewDidLoad];
#if TARGET_IPHONE_SIMULATOR
	ipLabel.text = [NSString stringWithFormat: @"ftp://%@:2121", [self getIPAddress]];
#else
    ipLabel.text = [NSString stringWithFormat: @"ftp://%@", [self getIPAddress]];
#endif
}

- (void) showFtpActivity: (BOOL) on {
	spinner.hidden = !on;
}

- (BOOL)shouldAutorotateToInterfaceOrientation:(UIInterfaceOrientation)interfaceOrientation {
	return YES;
}

- (void)didReceiveMemoryWarning {
    [super didReceiveMemoryWarning];
}

- (void)viewDidUnload {

}

- (void)dealloc {
    [super dealloc];
}

@end
