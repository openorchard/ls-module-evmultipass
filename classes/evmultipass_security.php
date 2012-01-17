<?php
/**
 * evMultiPass_Security.php
 *
 * @author Joe Richardson
 */


	/**
	 * EHLo MultiPass security class.
	 * This class extends the standard PHP Road Security class.
	 *
	 * This allows you to support multiple kinds of authentication
	 * providers.
	 *
	 */
	class evMultiPass_Security extends Phpr_Security
	{
		
		public $cookieName = "eCommerce";
		protected $cookieLifetimeVar = 'FRONTEND_AUTH_COOKIE_LIFETIME';

		protected $cookie_updated = false;
		
		protected $provider = null;

		protected $providerName = null;

		protected $providerClass = 'Core_FrontEndSecurity';

		/**
		 * Validates user login name and password and logs user in.
		 *
		 * @param string $Login Specifies the user login name.
		 * If you omit this parameter the 'Login' POST variable will be used.
		 *
		 * @param string $Password Specifies the user password
		 * If you omit this parameter the 'Password' POST variable will be used.
		 *
		 * @param string $Redirect Optional URL to redirect the user browser in case of successful login.
		 * @param Phpr_Validation $Validation Optional validation object to report errors.
		 *
		 * @return boolean
		 */
		public function login(Phpr_Validation $Validation = null, $Redirect = null, $Login = null, $Password = null, $Provider = null)
		{
				
			$this->getProvider($Provider);

			return $this->provider->login($Validation, $Redirect, $Login, $Password);
		}

		public function getUser()
		{
			if ( $this->user !== null )
				return $this->user;

			/*
			 * Determine whether the authentication cookie is available
			 */

			$CookieName = Phpr::$config->get('FRONTEND_AUTH_COOKIE_NAME', $this->cookieName);
			$Ticket = Phpr::$request->cookie( $CookieName );

			if ( $Ticket === null )
			{
				/*
				 * Check whether the front-end ticket was passed as a GET parameter
				 */
				$frontend_ticket_param = Phpr::$config->get('TICKET_PARAM_NAME', 'ls_frontend_ticket');
				$Ticket = $this->restoreTicket(Phpr::$request->getField($frontend_ticket_param));
			}
			
			if (!$Ticket)
				return null;


			/*
			 * Validate the ticket
			 */
			$Ticket = $this->validateTicket( $Ticket );
			if ( $Ticket === null )
				return null;


			if(is_array($Ticket['params']))
			{
			
				if(!empty($Ticket['params'][0]))
				{
					$Ticket['provider'] = $Ticket['params'][0];
				}

			}elseif(!empty($Ticket['params']))
			{
				$Ticket['provider'] = $Ticket['params'];
			}
			
			/**
			 * Determine which method of authentication was used
			 * when the user was first authenticated.
			 */
			$this->getProvider(isset($Ticket['provider'])?$Ticket['provider']:null);

			/*
			 * Return the ticket user
			 */
			$UserId = trim(base64_decode($Ticket['user']));
			if ( !strlen($UserId) )
				return null;
			
			return $this->provider->findUser($UserId);
		}

		/**
		 * Validates authorization ticket
		 * @param string $Ticket Specifies an authorization ticket
		 * @return array Returns parsed ticket information if it is valid or null
		 */
		public function validateTicket( $Ticket, $cacheTicket = false )
		{
			if ($cacheTicket)
				$this->_ticket = $Ticket;
				
			$Ticket = base64_decode($Ticket);

			$parts = explode('|', $Ticket);
			if (count($parts) < 3)
				return null;
			
			$Ticket .= '|';

			list( $id, $expiration, $hmac, $params) = explode( '|', $Ticket );

			$id_decoded = base64_decode($id);
			
			if ( $expiration < time() )
				return null;

			$key = hash_hmac( 'md5', $id_decoded.$expiration, Phpr_SecurityFramework::create()->salt() );
			$hash = hash_hmac( 'md5', $id_decoded.$expiration, $key );

			if ( $hmac != $hash )
				return null;

			
			return array('user'=>$id,'params'=>$params);
		}

		/*
		 * Returns the authorization ticket for a specified user
		 * @param int $Id Specifies a user identifier
		 * @return string
		 */
		public function getTicket( $Id = null )
		{
			if ( $Id === null )
			{
				$User = $this->getUser();
				if ( !$User )
					return null;

				$Id = $User->id;
			}

			$lifetime = Phpr::$config->get($this->cookieLifetimeVar, $this->cookieLifetime);
			$lifetime = $lifetime > 0 ? $lifetime*24*3600 : 3600;
			
			$params = '';
			if(!empty($this->providerName)){
				$params = '|' . $this->providerName; 
			}

			$expiration = time()+$lifetime;

			$key = hash_hmac('md5', $Id.$expiration, Phpr_SecurityFramework::create()->salt());
			$hash = hash_hmac('md5', $Id.$expiration, $key);
			$ticket = base64_encode(base64_encode($Id).'|'.$expiration.'|'.$hash . $params);

			return $ticket;
		}


		protected function getProvider($provider = null)
		{
		
			if(!is_null($provider))
			{
				$this->providerName = $provider;
				$this->providerClass = $provider . '_Security';	
			}
			

			return $this->provider = new $this->providerClass();
		}

		public function authorize_user()
		{
			
			if (!$this->check_session_host())
				return null;

			$user = $this->getUser();
			

			if (!$user)
				return null;

			if (!$this->cookie_updated)
			{
				$this->updateCookie( $user->id );
				$this->cookie_updated = true;
			}


			return $user;
		}

		protected function updateCookie($Id)
		{
			/*
			 * Prepare the authentication ticket
			 */
			$Ticket = $this->getTicket( $Id );

			/*
			 * Set a cookie
			 */
			$CookieName = Phpr::$config->get('FRONTEND_AUTH_COOKIE_NAME', $this->cookieName);
			$CookieLifetime = Phpr::$config->get($this->cookieLifetimeVar, $this->cookieLifetime);

			$CookiePath = Phpr::$config->get('FRONTEND_AUTH_COOKIE_PATH', $this->cookiePath);
			$CookieDomain = Phpr::$config->get('FRONTEND_AUTH_COOKIE_DOMAIN', $this->cookieDomain);

			Phpr::$response->setCookie( $CookieName, $Ticket, $CookieLifetime, $CookiePath, $CookieDomain );
		}
		
		public function customerLogin($CustomerId)
		{
			$this->updateCookie($CustomerId);
			Backend::$events->fireEvent('onFrontEndLogin');
		}

		public function logout($Redirect = null)
		{
			$CookieName = Phpr::$config->get('FRONTEND_AUTH_COOKIE_NAME', $this->cookieName);
			$CookiePath = Phpr::$config->get('FRONTEND_AUTH_COOKIE_PATH', $this->cookiePath);
			$CookieDomain = Phpr::$config->get('FRONTEND_AUTH_COOKIE_DOMAIN', $this->cookieDomain);

			Phpr::$response->deleteCookie( $CookieName, $CookiePath, $CookieDomain );

			$this->user = null;

			Phpr::$session->destroy();

			if ( $Redirect !== null )
				Phpr::$response->redirect( $Redirect );
		}

		protected function beforeLoginSessionDestroy($user)
		{
			Backend::$events->fireEvent('onFrontEndLogin');
		}
		
		protected function keepSessionData()
		{
			return strlen(Shop_CheckoutData::get_coupon_code());
		}

		public function findUser($UserId)
		{
			if (isset(self::$UserCache[$UserId]))
				return self::$UserCache[$UserId];
			
			return self::$UserCache[$UserId] = Shop_Customer::create()->where('deleted_at is null')->where('shop_customers.id=?', $UserId)->find();
		}
	}
	
