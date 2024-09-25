# accuknox_Backend
installation steps
- docker-compose build
- docker-compose up


1. JWT Auth
    installed  djangorestframework-simplejwt library
    Config is
    ```
    SIMPLE_JWT = {
        'ACCESS_TOKEN_LIFETIME': timedelta(minutes=5),
        'REFRESH_TOKEN_LIFETIME': timedelta(days=1),
        'ROTATE_REFRESH_TOKENS': True,  # Optional: Rotate refresh tokens
        'BLACKLIST_AFTER_ROTATION': True,  # Optional: Blacklist old refresh tokens
    }
    ```
2. Rate Limiting
    "DEFAULT_THROTTLE_RATES": {"user": "3/min", "connections.request": "3/min"},
3. RBAC
    Created 3 groups using fixtures in /accounts/fixtures/group.json
    On Signup role [1,2,3] is taken to decide whether read/write or Admin access is given (default is Admin)
    Created Custom DRF permission to test if Read (only GET), Wite(GET, PATCH,PUT), Admin(No restriction)
    ``` 
        if method in ["post", "put", "patch"] and pk in [1, 2]:
            return True
        if method == "delete" and pk == 1:
            return True
        if method == "get":
            return True
        return False
    ```
4. Paginator using  ``` from django.core.paginator import Paginator```
5. Searching is done on name and email, both of them are indexed
6. Caching is implemented using ``` from django.core.cache import cache ```
    ```
    cache_key = f"friend_list_{request.user.id}"
    cached_data = cache.get(cache_key)
    if cached_data is not None:
        return custom_success_response(cached_data)
    ```
7. Atomic Transaction using ``` from django.db import transaction ``` used -> ```with transaction.atomic() ```
## Architecture
## request's -> response is made common for all drf Response in file accuknox/utils.py