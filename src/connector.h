/*
 * Copyright 2014-2016 Con Kolivas
 *
 * This program is free software; you can redistribute it and/or modify it
 * under the terms of the GNU General Public License as published by the Free
 * Software Foundation; either version 3 of the License, or (at your option)
 * any later version.  See COPYING for more details.
 */

#ifndef CONNECTOR_H
#define CONNECTOR_H

void connector_add_message(ckpool_t *ckp, json_t *val);
void *connector(void *arg);

#endif /* CONNECTOR_H */
