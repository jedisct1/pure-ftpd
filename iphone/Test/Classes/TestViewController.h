//
//  TestViewController.h
//  Test
//
//  Created by Frank Denis on 29/10/09.
//  Copyright __MyCompanyName__ 2009. All rights reserved.
//

#import <UIKit/UIKit.h>

@interface TestViewController : UIViewController {
	UILabel *ipLabel;
	UIActivityIndicatorView *spinner;
}

@property (nonatomic, retain) IBOutlet UILabel *ipLabel;
@property (nonatomic, retain) IBOutlet UIActivityIndicatorView *spinner;

- (IBAction) onoffSwitchMoved: (id) sender;
- (void) showFtpActivity: (BOOL) on;

@end

