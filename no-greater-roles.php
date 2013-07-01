<?php
/*
Plugin Name: No greater roles
Plugin URI: http://www.bellefondblog.com/no-greater-roles/
Description: Prevents the creation of users with roles more important than the connected user and hides users with roles more important than the connected user in the administration "users" section
Version: 1.0
Author: Benoît Rouches
Author URI: http://www.bellefondblog.com
License: GPL2
*/

/*  Copyright 2013  Benoît Rouches  (email : benoitrouches@gmail.com)

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License, version 2, as 
    published by the Free Software Foundation.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA
*/


/**
 * Retourne la valeur du niveau (maximum) d'un rôle
 *
 * @param  string $role
 * @return int|null
 */		 
function  no_greater_roles_getLevel($role) {
	
	global $wp_roles;
	
	$capabilities = isset($wp_roles->roles[$role]['capabilities']) 
							? $wp_roles->roles[$role]['capabilities']
							: false;
	
	if(!$capabilities)
	return;
	
	$level = array();			
	
	for($i = 0; $i <= 10; $i++) {
	
		if(array_key_exists('level_' . $i, $capabilities))
		$level[] = $i;
	}
	
	if(!empty($level))
	return max($level);
}		

/**
 * Empêche l'affichage des rôles supérieurs à celui
 * de l'utilisateur connecté dans les champs select des pages user-new.php et user-edit.php
 *
 * @param  array $editable_roles
 * @return array
 */
function no_greater_roles_editable_roles_filter($editable_roles) {

	global $pagenow;
	global $current_user;

	if(!in_array($pagenow, array('user-new.php', 'user-edit.php')) || current_user_can('administrator'))
	return $editable_roles;
    			
	$currentUserRole      = key($current_user->caps);
	$currentUserRoleLevel = no_greater_roles_getLevel($currentUserRole);

	foreach(array_keys($editable_roles) as $role) {
	
		if(no_greater_roles_getLevel($role) > $currentUserRoleLevel)
		unset( $editable_roles[$role] );
	}
	
   return $editable_roles;
}
add_filter('editable_roles', 'no_greater_roles_editable_roles_filter');	

/**
 * Empêche la récupération des utilisateurs dont le rôle est supérieur à celui
 * de l'utilisateur connecté, donc leur affichage dans la table des utilisateurs de la page users.php
 *
 * @param  WP_User_Query $wp_user_query
 * @return void|null
 */
function no_greater_roles_pre_user_query($wp_user_query) {

	global $pagenow;
	global $wpdb;
	
	if('users.php' != $pagenow || current_user_can('administrator'))
	return;

	$current_user         = wp_get_current_user();
	$currentUserRole      = array_shift($current_user->roles);
	$currentUserRoleLevel = no_greater_roles_getLevel($currentUserRole);
	
	$users                = $wpdb->get_results("SELECT * FROM $wpdb->users");
	
	$usersToExclude = array();

	foreach ($users as $user) { 
		$role = key(get_user_meta($user->ID, 'wp_capabilities', true));
		if(no_greater_roles_getLevel($role) > $currentUserRoleLevel)
		$usersToExclude[] = $user->ID;
	}

	if(!empty($usersToExclude)) {
		$wp_user_query->query_where = str_replace('WHERE 1=1', 'WHERE 1=1 AND ' . $wpdb->users . '.ID NOT IN (' . implode(',', $usersToExclude) .')  ', $wp_user_query->query_where);
	}
}	
add_action('pre_user_query','no_greater_roles_pre_user_query');

/**
 * Masque en utilisant css le menu permettant de trier les utilisateurs par rôle 
 *
 * @return void|null
 */		
function no_greater_roles_admin_head_hide_subsubsub(){

	global $pagenow;
	
	if('users.php' != $pagenow)
	return;
	
	if (!current_user_can('administrator')) 
	echo '<style> .subsubsub { display:none; } </style>';		
}
add_action('admin_head', 'no_greater_roles_admin_head_hide_subsubsub');				

/**
 * Restreint l'accès à la page user-edit.php 
 * aux utilisateurs dont le rôle est inférieur à celui du profil édité
 *
 * @return void|null
 */
function no_greater_roles_user_edit_restrict() {
	
	global $pagenow;

	if($pagenow != 'user-edit.php' || current_user_can('administrator'))
	return;

	$user_id = isset($_REQUEST['user_id']) ? $_REQUEST['user_id'] : false ;
	
	if($user_id) {
		
		$role = get_user_meta($user_id, 'wp_capabilities', true);
		
		if(empty($role))
		return;
			
		$roleLevel            =  no_greater_roles_getLevel(key($role));
		
		$current_user         = wp_get_current_user();
		$currentUserRole      = array_shift($current_user->roles);
		$currentUserRoleLevel = no_greater_roles_getLevel($currentUserRole);

		if($currentUserRoleLevel >= $roleLevel)
		return;
	}

	wp_redirect( admin_url('users.php') );
	exit;
}
add_action('admin_init', 'no_greater_roles_user_edit_restrict');

/**
 * Restreint l'accès à la page users.php en supression 
 * aux utilisateurs dont le rôle est inférieur à celui du profil que l'on veut supprimer
 *
 * @return void|null
 */		
function no_greater_roles_delete_user_restrict() {

	global $pagenow;

	if($pagenow != 'users.php' || current_user_can('administrator'))
	return;
	
	$user_id = isset($_REQUEST['user']) ? $_REQUEST['user'] : false ;
	
	if(!$user_id)
	return;
	
	$role = get_user_meta($user_id, 'wp_capabilities', true);

	if(empty($role))
	return;			
	
	$roleLevel      =  no_greater_roles_getLevel(key($role));

	$current_user         = wp_get_current_user();
	$currentUserRole      = array_shift($current_user->roles);
	$currentUserRoleLevel = no_greater_roles_getLevel($currentUserRole);

	if($currentUserRoleLevel >= $roleLevel)
	return;	
	
	wp_redirect( admin_url('users.php') );
	exit;
}
add_action('admin_init', 'no_greater_roles_delete_user_restrict');

/**
 * Permet de sécuriser les formulaires en empéchant la suppression des utilisateurs dont le rôle
 * est plus important que celui de l'utilisateur connecté et en interdisant d'attribuer des
 * rôles plus importants que ceux permis   
 *
 * @return void
 */
function no_greater_roles_securize_role() {
	
	global $pagenow; 
	
	if(in_array($pagenow, array('user-edit.php', 'users.php', 'user-new.php')) 
		&& $_SERVER['REQUEST_METHOD'] === 'POST'
		&& !current_user_can('administrator')
		)
	{
		if($pagenow == 'users.php' && isset($_POST['action']) && $_POST['action'] == 'dodelete' ) {			
			
			$user_id   = isset($_REQUEST['user']) ? $_REQUEST['user'] : null;
			$role      = get_user_meta($user_id, 'wp_capabilities', true);
			$roleLevel = !is_array($role) ? null : no_greater_roles_getLevel(key($role));

		} else {
			$role      = isset($_POST['role']) ? $_POST['role'] : null;
			$roleLevel = no_greater_roles_getLevel($role);
		}

		$current_user         = wp_get_current_user();
		$currentUserRole      = array_shift($current_user->roles);
		$currentUserRoleLevel = no_greater_roles_getLevel($currentUserRole);				
		
		if($roleLevel > $currentUserRoleLevel) {
			wp_redirect( admin_url('users.php') );
			exit;
		}
	}
}	
add_action('admin_init', 'no_greater_roles_securize_role');