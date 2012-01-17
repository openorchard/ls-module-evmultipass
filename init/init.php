<?php

/**
 * Init file for EHLOMultiPass
 *
 * 	Initializes the custom frontend security module which will
 * 	dynamically load other security models based on the 
 * 	
 * 	@author Joe Richardson
 *
 */


//Overwrite the frontend security that existed.
PHPr::$frontend_security = new EHLOMultiPass_Security();


