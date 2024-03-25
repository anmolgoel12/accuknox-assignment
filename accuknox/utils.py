from django.http import JsonResponse
from rest_framework import status


def custom_success_response(
    serialized_data,
    message="success",
    status=status.HTTP_200_OK,
    headers=None,
    **kwargs
):
    data = {}
    data["data"] = serialized_data
    for key, value in kwargs.items():
        data[key] = value
    data["status"] = "1"
    return JsonResponse(data, status=status, headers=headers)


def update_object_response(
    message="success ok", status=status.HTTP_200_OK, headers=None
):
    data = {}
    data["message"] = message
    data["status"] = "1"
    return JsonResponse(data, status=status, headers=headers)
