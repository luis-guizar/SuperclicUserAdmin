import logging
import os
from typing import Any, Dict, Optional, List

import httpx 
from fastapi import FastAPI, HTTPException, status, Depends
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel, EmailStr, field_validator # Keep field_validator
from dotenv import load_dotenv
from supabase import create_client, Client # Added Client import
from supabase.lib.client_options import ClientOptions
from gotrue.errors import AuthApiError # More specific error type for Auth
from postgrest.exceptions import APIError # Error type for Postgrest (table operations)



load_dotenv()

SUPABASE_URL = os.getenv("SUPABASE_URL")
SUPABASE_SERVICE_ROLE_KEY = os.getenv("SUPABASE_SERVICE_ROLE_KEY")

# Check for Supabase variables specifically
if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
    logging.critical("Missing required Supabase environment variables (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)")
    raise EnvironmentError("Missing required Supabase environment variables (SUPABASE_URL, SUPABASE_SERVICE_ROLE_KEY)")

# --- Configure Logging ---
logging.basicConfig(
    level=logging.DEBUG, # Consider changing to INFO for production
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s',
)
logger = logging.getLogger(__name__)
logger.debug("Logger configured successfully.")


class UserCreateRequest(BaseModel):
    full_name: str
    email: EmailStr
    phone: Optional[str] = None
    password: str
    suscriptoruuid: Optional[str] = None
    arrayDerechos: List[int] = []
    avatar_url: Optional[str] = None
    rfc: Optional[str] = None
    status_code: int = 1
    puesto_concepto: Optional[str] = None
    puesto_uuid: Optional[str] = None
    flag_admin: Optional[bool] = False
    sucursal_default_uuid: Optional[str] = None
    sucursales_uuids: Optional[List[str]] = None


    # Using Pydantic v2 validator style
    @field_validator("password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        # Add more checks if needed (uppercase, number, symbol)
        return v



class ProfileUpdateRequest(BaseModel):
    user_id: str
    full_name: str
    email: EmailStr
    phone: Optional[str] = None
    suscriptoruuid: Optional[str] = None
    arrayDerechos: List[int] = [] 
    avatar_url: Optional[str] = None
    rfc: Optional[str] = None
    status_code: int = 1
    puesto_concepto: Optional[str] = None
    puesto_uuid: Optional[str] = None
    flag_admin: Optional[bool] = False
    sucursal_default_uuid: Optional[str] = None
    sucursales_uuids: Optional[List[str]] = None

    @field_validator("suscriptoruuid", "puesto_uuid", mode="before")
    @classmethod
    def empty_str_to_none(cls, v: Any) -> Optional[str]:
        """Convert empty strings for UUID fields to None."""
        if isinstance(v, str) and v == "":
            return None

        return v

class UserDeleteResponse(BaseModel):
    message: str

class PasswordResetRequest(BaseModel):
    user_id: str
    new_password: str

    @field_validator("new_password")
    @classmethod
    def password_strength(cls, v):
        if len(v) < 6:
            raise ValueError("Password must be at least 6 characters long")
        # Add more checks if needed
        return v

class PasswordResetResponse(BaseModel):
    message: str

# --- FastAPI App ---
app = FastAPI(
    title="User Management API",
    description="API for managing users with Supabase backend",
    version="1.0.0"
)

# --- CORS Configuration ---
origins = [ "http://localhost","https://superclic.app"]

app.add_middleware(
    CORSMiddleware,
    allow_origins=origins, 
    allow_credentials=True,
    allow_methods=["*"], 
    allow_headers=["*"], 
)

_supabase_client: Optional[Client] = None

def get_supabase_client_instance() -> Client:
    """Initializes and returns a Supabase client instance."""
    global _supabase_client
    if _supabase_client is None:
        if not SUPABASE_URL or not SUPABASE_SERVICE_ROLE_KEY:
            logging.error("Supabase URL or Key not configured for client creation.")
            # Raising ValueError here will be caught by FastAPI/Starlette startup usually
            raise ValueError("Supabase URL/Key not configured.")
        try:
            # Client creation is synchronous
            _supabase_client = create_client(
                SUPABASE_URL,
                SUPABASE_SERVICE_ROLE_KEY,
                options=ClientOptions(
                    auto_refresh_token=False, 
                    persist_session=False,    
                )
            )
            logger.info("Supabase client initialized successfully.")
        except Exception as e:
            logger.critical(f"CRITICAL: Failed to initialize Supabase client: {e}", exc_info=True)
            _supabase_client = None 
            raise RuntimeError(f"Could not initialize Supabase client: {e}") from e # Raise runtime error to potentially stop startup
            
    if _supabase_client is None:
         logger.error("Attempted to get Supabase client, but it was not initialized.")
         raise HTTPException(
             status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
             detail="Supabase client is not available."
         )
    return _supabase_client


async def get_supabase() -> Client: 
    """FastAPI dependency to get the initialized Supabase client."""
    try:
        client = get_supabase_client_instance()
        yield client
    except (ValueError, RuntimeError, HTTPException) as e:
         logger.error(f"Error providing Supabase client dependency: {e}")
         if isinstance(e, HTTPException):
             raise e 
         else:
             raise HTTPException(
                 status_code=status.HTTP_503_SERVICE_UNAVAILABLE,
                 detail=f"Supabase client unavailable: {str(e)}"
             )
    except Exception as e:
        logger.error(f"Unexpected error in get_supabase dependency: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="Internal error obtaining Supabase client."
        )

# --- API Endpoints ---

@app.delete("/delete-user/{user_id}",
            response_model=UserDeleteResponse,
            status_code=status.HTTP_200_OK,
            summary="Delete User Account and Mark Profile Inactive",
            tags=["User Management"])
async def delete_user(user_id: str, supabase: Client = Depends(get_supabase)):
    """
    Deletes a user from Supabase Auth and sets their status_code to 0
    in the 'profiles' table.

    Requires the user_id of the user to delete.

    **Authorization Note:** This endpoint uses the service role key and can delete *any* user.
    Implement proper authorization checks for production use.
    """
    logger.info(f"Attempting to delete user with ID: {user_id}")

    try:
        response = supabase.auth.admin.update_user_by_id(
            user_id,
    {
        'ban_until':'2035-04-22T16:34:23-06:00',
    }
)
        logger.info(f"Successfully deleted user from Supabase Auth: {user_id}")

        update_response = (
            supabase.table("profiles")
            .update({"status_code": 0})  
            .eq("id", user_id)  
            .execute()
        )
        
        if hasattr(update_response, 'error') and update_response.error:
             logger.error(f"Supabase table update failed for user {user_id} after auth deletion: {update_response.error}")
             raise HTTPException(
                 status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                 detail=f"User {user_id} deleted from Auth, but failed to update status in 'profiles'. Please check logs.",
             )
        if not update_response.data:
            logger.warning(f"User {user_id} deleted from Auth, but no matching row found in 'profiles' table to update status.")
            return UserDeleteResponse(message=f"User {user_id} deleted from Auth, but no profile found in 'profiles' to update.")

        logger.info(f"Successfully marked user {user_id} as inactive in 'profiles' table.")
        return UserDeleteResponse(message=f"User {user_id} deleted and status updated successfully")

    except AuthApiError as e:
        logger.error(f"Supabase Auth API error while deleting user {user_id}: {e.message} (Status: {e.status})", exc_info=False) # exc_info=False for potentially sensitive data
        status_code = e.status if hasattr(e, 'status') else status.HTTP_500_INTERNAL_SERVER_ERROR
        detail = f"Authentication service error: {e.message}"
        if e.status == 404:
            status_code = status.HTTP_404_NOT_FOUND
            detail = f"User with ID {user_id} not found in Authentication."
        elif e.status == 400:
             status_code = status.HTTP_400_BAD_REQUEST

        raise HTTPException(status_code=status_code, detail=detail)
    except APIError as e: 
        logger.error(f"Supabase Table API error during user deletion process for {user_id}: {e.message}", exc_info=True)
        raise HTTPException(
             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
             detail=f"Database table error after auth deletion for {user_id}: {e.message}",
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error while deleting user {user_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred while processing user {user_id}.",
        )

@app.post("/create-user",
          status_code=status.HTTP_201_CREATED,
          summary="Create New User Account and Profile",
          tags=["User Management"])
async def create_user(user_data: UserCreateRequest, supabase: Client = Depends(get_supabase)):
    """
    Creates a new user in Supabase Auth and a corresponding profile
    in the 'profiles' table.

    **Authorization Note:** Uses service role key. Implement authorization if needed.

    **Confirmation Note:** By default, `email_confirm` and `phone_confirm` are set to `True`,
    bypassing standard verification flows. Change if verification is required.

    **Metadata Note:** Includes profile details in `user_metadata`. Review if needed.
    """
    logger.info(f"Attempting to create user with email: {user_data.email}")
    user_id = None # Initialize user_id

    try:
        # --- 1. Create User in Supabase Auth ---
        user_metadata_payload = {
            "nombre": user_data.full_name,
            "email": user_data.email,
            "phone": user_data.phone,
            "suscriptoruuid": user_data.suscriptoruuid,
            "arrayDerechos": user_data.arrayDerechos,
            "avatar_url": user_data.avatar_url, 
            "rfc": user_data.rfc,
            "puesto_concepto": user_data.puesto_concepto,
            "puesto_uuid": user_data.puesto_uuid,
            "flag_admin": user_data.flag_admin,
            "sucursal_default_uuid": user_data.sucursal_default_uuid,
            "sucursales_uuids": user_data.sucursales_uuids,
        }

        auth_response = supabase.auth.admin.create_user(
            {
                "email": user_data.email,
                "password": user_data.password,
                "user_metadata": user_metadata_payload,
                "email_confirm": True, 
                "phone": user_data.phone,
                "phone_confirm": True
            }
        )

        if not hasattr(auth_response, 'user') or not auth_response.user or not auth_response.user.id:
            logger.error(f"User creation in Auth failed or returned unexpected response for email {user_data.email}. Response: {auth_response}")
            # Attempt to extract potential error messages if available
            error_detail = "User creation failed in Auth, unexpected response structure."
            if hasattr(auth_response, 'error') and auth_response.error:
                 error_detail = f"User creation failed in Auth: {auth_response.error}"
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
                detail=error_detail,
            )

        user_id = auth_response.user.id
        logger.info(f"User created successfully in Supabase Auth with ID: {user_id}")

        # --- 2. Create Profile in 'profiles' Table ---
        profile_data = user_data.model_dump(exclude={"password"}) 
        profile_data["id"] = user_id 



        profile_data.setdefault("status_code", user_data.status_code)
        profile_data.setdefault("flag_admin", user_data.flag_admin)
        profile_data.setdefault("sucursal_default_uuid", user_data.sucursal_default_uuid)
        profile_data.setdefault("sucursales_uuids", user_data.sucursales_uuids)
        profile_data.setdefault("arrayDerechos", user_data.arrayDerechos)

        logger.info(f"Creating profile in 'profiles' for user ID: {user_id}")
        insert_response = supabase.table("profiles").insert(profile_data).execute()

        if hasattr(insert_response, 'error') and insert_response.error:
            logger.error(f"Error creating profile in 'profiles' table for user {user_id}: {insert_response.error}")
            # ROLLBACK: Attempt to delete the already created Auth user for consistency
            logger.warning(f"Rolling back Auth user creation for {user_id} due to profile insertion failure.")
            try:
                 supabase.auth.admin.delete_user(user_id)
                 logger.info(f"Successfully rolled back Auth user {user_id}.")
            except AuthApiError as rollback_error:
                 logger.error(f"CRITICAL: Failed to rollback Auth user {user_id} after profile creation error: {rollback_error.message}", exc_info=True)

            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST, # Or 500 if internal error
                detail=f"Error creating profile in 'profiles' table: {insert_response.error.get('message', 'Unknown error')}",
            )

        logger.info(f"Successfully created profile in 'profiles' for user ID: {user_id}")
        return {"message": "User created successfully", "user_id": user_id, "email": user_data.email}

    except AuthApiError as e:
        logger.error(f"Supabase Auth API error during user creation for {user_data.email}: {e.message} (Status: {e.status})", exc_info=False)
        status_code = e.status if hasattr(e, 'status') else status.HTTP_500_INTERNAL_SERVER_ERROR
        detail = f"Authentication service error: {e.message}"
        if e.status == 400 or e.status == 422 or ("already registered" in e.message.lower()):
            status_code = status.HTTP_409_CONFLICT
            detail = f"User with email {user_data.email} already exists."

        if user_id:
             logger.warning(f"Attempting potential rollback for partially created user {user_id} after Auth error {e.status}")
             try:
                 supabase.auth.admin.delete_user(user_id)
                 logger.info(f"Rollback successful for user {user_id} after Auth error.")
             except Exception as rb_err:
                 logger.error(f"Failed during potential rollback for user {user_id}: {rb_err}")

        raise HTTPException(status_code=status_code, detail=detail)
    except APIError as e: 
        logger.error(f"Supabase Table API error during profile creation for {user_data.email}: {e.message}", exc_info=True)
        # If user_id is known, Auth user was created, attempt rollback
        if user_id:
            logger.warning(f"Rolling back Auth user creation for {user_id} due to profile insertion failure (APIError).")
            try:
                 supabase.auth.admin.delete_user(user_id)
                 logger.info(f"Successfully rolled back Auth user {user_id}.")
            except AuthApiError as rollback_error:
                 logger.error(f"CRITICAL: Failed to rollback Auth user {user_id} after profile creation error: {rollback_error.message}", exc_info=True)
        raise HTTPException(
             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, 
             detail=f"Database table error during profile creation: {e.message}",
        )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during user creation for {user_data.email}: {e}", exc_info=True)
        if user_id:
            logger.warning(f"Rolling back potentially created Auth user {user_id} due to unexpected error.")
            try:
                 supabase.auth.admin.delete_user(user_id)
                 logger.info(f"Successfully rolled back potentially created Auth user {user_id}.")
            except Exception as rollback_error:
                 logger.error(f"CRITICAL: Failed to rollback potentially created Auth user {user_id}: {rollback_error}", exc_info=True)

        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during user creation: {str(e)}",
        )


@app.put("/update-profile",
         status_code=status.HTTP_200_OK,
         summary="Update User Profile Data",
         tags=["User Management"])
async def update_profile(profile_data: ProfileUpdateRequest, supabase: Client = Depends(get_supabase)):
    """
    Updates fields in the 'profiles' table for a given user_id.
    Only fields provided in the request body will be updated.

    **Authorization Note:** Requires service role key. Implement checks to ensure
    a user can only update their own profile or that the caller is an admin.
    """
    user_id = profile_data.user_id
    logger.info(f"Attempting to update profile for user ID: {user_id}")

    try:
        # Create payload excluding user_id and None values
        update_payload: Dict[str, Any] = profile_data.model_dump(exclude={"user_id"}, exclude_unset=True)

        if not update_payload:
            logger.warning(f"No update data provided for user ID: {user_id}")
            raise HTTPException(
                status_code=status.HTTP_400_BAD_REQUEST,
                detail="No fields provided for update.",
            )


        update_response = supabase.table('profiles').update(update_payload).eq('id', user_id).execute()


        if hasattr(update_response, 'error') and update_response.error:
            logger.error(f"Supabase DB error updating profile for user {user_id}: {update_response.error}")
            raise HTTPException(
                status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, # Or 400 if constraint violation etc.
                detail=f"Error updating user profile in DB: {update_response.error.get('message', 'Unknown DB error')}",
            )

        if not update_response.data:
            logger.warning(f"Profile update attempt for user ID {user_id}: User not found in 'profiles' or no changes applied.")
            # Check if user exists in Auth to differentiate
            try:
                supabase.auth.admin.get_user_by_id(user_id)
                # User exists in Auth but not in profiles table
                detail = f"Profile for user ID {user_id} not found in 'profiles' table."
            except AuthApiError:
                 # User doesn't exist in Auth either
                 detail = f"User with ID {user_id} not found."

            raise HTTPException(
                status_code=status.HTTP_404_NOT_FOUND,
                detail=detail,
            )

        logger.info(f"Profile updated successfully for user ID: {user_id}")

        # Return the updated data record
        return {
            "message": "User profile updated successfully",
            "user_id": user_id,
            "updated_data": update_response.data[0] # Return the actual updated record
        }

    except APIError as e: # Catch Postgrest errors
         logger.error(f"Supabase Table API error during profile update for {user_id}: {e.message}", exc_info=True)
         raise HTTPException(
             status_code=status.HTTP_500_INTERNAL_SERVER_ERROR, # Or 400/404 depending on error
             detail=f"Database table error during profile update: {e.message}",
         )
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during profile update for {user_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail="An unexpected internal error occurred while updating the profile.",
        )


@app.post("/reset-password",
          response_model=PasswordResetResponse,
          status_code=status.HTTP_200_OK,
          summary="Reset User Password (Admin)",
          tags=["User Management"])
async def reset_password(password_data: PasswordResetRequest, supabase: Client = Depends(get_supabase)):
    """
    Resets the password for a given user_id using the admin role.

    **Authorization Note:** Requires service role key. Implement checks if needed.
    """
    user_id = password_data.user_id
    logger.info(f"Attempting password reset for user ID: {user_id}")

    try:

        response = supabase.auth.admin.update_user_by_id(
            user_id,
            {"password": password_data.new_password}
        )


        logger.info(f"Password reset successfully for user ID: {user_id}")
        return PasswordResetResponse(message="Password has been reset successfully")

    except AuthApiError as e:
        logger.error(f"Supabase Auth API error during password reset for {user_id}: {e.message} (Status: {e.status})", exc_info=False)
        status_code = e.status if hasattr(e, 'status') else status.HTTP_500_INTERNAL_SERVER_ERROR
        detail = f"Authentication service error: {e.message}"
        if e.status == 404:
            status_code = status.HTTP_404_NOT_FOUND
            detail = f"User with ID {user_id} not found for password reset."
        elif e.status == 422: # Often used for validation errors (e.g., weak password)
             status_code = status.HTTP_422_UNPROCESSABLE_ENTITY
             detail = f"Invalid data for password reset: {e.message}" # Or more generic
        elif e.status == 400:
             status_code = status.HTTP_400_BAD_REQUEST

        raise HTTPException(status_code=status_code, detail=detail)
    except HTTPException as e:
        raise e
    except Exception as e:
        logger.error(f"Unexpected error during password reset for {user_id}: {e}", exc_info=True)
        raise HTTPException(
            status_code=status.HTTP_500_INTERNAL_SERVER_ERROR,
            detail=f"An unexpected error occurred during password reset.",
        )

# --- Run the App ---
if __name__ == "__main__":
    import uvicorn
    uvicorn.run("SuperclicUserAdmin:app", host="0.0.0.0", port=3334, reload=True)
