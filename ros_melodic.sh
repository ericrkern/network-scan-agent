#!/bin/bash

xhost +

docker run -it \
--net=host \
-e DISPLAY=$DISPLAY \
-e "QT_X11_NO_MITSHM=1" \
-v /tmp/.X11-unix:/tmp/.X11-unix \
-v /home/jetson/share:/share \
--device=/dev/video0 \
yahboomtechnology/ros-melodic:usb_cam /bin/bash
