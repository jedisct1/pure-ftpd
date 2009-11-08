//
//  TestAppDelegate.h
//  Test
//
//  Created by Frank Denis on 29/10/09.
//  Copyright __MyCompanyName__ 2009. All rights reserved.
//

#import <UIKit/UIKit.h>

@class TestViewController;

@interface TestAppDelegate : NSObject <UIApplicationDelegate> {
    UIWindow *window;
    TestViewController *viewController;
	BOOL ftpOn;
	NSNetService *ftpService;
}

@property (nonatomic, retain) IBOutlet UIWindow *window;
@property (nonatomic, retain) IBOutlet TestViewController *viewController;
@property (assign) BOOL ftpOn;
@property (retain) NSNetService *ftpService;

@end

