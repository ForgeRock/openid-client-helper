/**
 * Utilities module.
 * @private
 * @module utilities
 */

'use strict'

/**
 * @returns {object} Object containing utility functions.
 */
module.exports = {
  /**
   * Copies object properties converted to JSON.
   * Undefined properties will be ignored.
   * @param {object} object1 A target object.
   * @param {object} object2 A source object.
   * @returns {object} The target object.
   * @alias module:utilities#assignJSON
   */
  assignJSON: (object1, object2) => {
    return Object.assign(object1, JSON.parse(JSON.stringify(object2 || {})))
  },
  /**
   * Returns a property of an object.
   * @param {object} obj Object containing the property.
   * @param {string} key Path to the object property expressed via a dot notation.
   * @returns {any} A found property value or undefined.
   * @alias module:utilities#getProperty
   */
  getProperty: (obj, key) => {
    var keyArray

    if (typeof key.split === 'function') {
      keyArray = key.split('.')
    } else {
      keyArray = [key]
    }

    return keyArray.reduce((initial, current) => {
      if (!initial) {
        return initial
      }

      return initial[current]
    }, obj)
  },
  /**
   * Assigns a value to a property of an object.
   * @param {object} obj The object.
   * @param {string} key Path to the property expressed via a dot notation.
   * @param {any} value The value to be assigned.
   * @returns {any} The value associated with the property.
   * @alias module:utilities#setProperty
   */
  setProperty: (obj, key, value) => {
    var keyArray

    if (typeof key.split === 'function') {
      keyArray = key.split('.')
    } else {
      keyArray = [key]
    }

    return keyArray.reduce((initial, current, index, array) => {
      if (array.length - index > 1) {
        if (!initial[current]) {
          initial[current] = {}
        }
      } else {
        initial[current] = value
      }

      return initial[current]
    }, obj)
  }
}
