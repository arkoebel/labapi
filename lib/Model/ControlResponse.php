<?php
/**
 * ControlResponse
 *
 * PHP version 5
 *
 * @category Class
 * @package  Swagger\Server
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */

/**
 * LAB contrôle API swagger
 *
 * API LAB contrôle des virements et prélèvements
 *
 * OpenAPI spec version: 1.0.0
 * 
 * Generated by: https://github.com/swagger-api/swagger-codegen.git
 * Swagger Codegen version: 2.4.29
 */

/**
 * NOTE: This class is auto generated by the swagger code generator program.
 * https://github.com/swagger-api/swagger-codegen
 * Do not edit the class manually.
 */

namespace Swagger\Server\Model;

use \ArrayAccess;
use \Swagger\Server\ObjectSerializer;

/**
 * ControlResponse Class Doc Comment
 *
 * @category Class
 * @package  Swagger\Server
 * @author   Swagger Codegen team
 * @link     https://github.com/swagger-api/swagger-codegen
 */
class ControlResponse implements ModelInterface, ArrayAccess
{
    const DISCRIMINATOR = null;

    /**
      * The original name of the model.
      *
      * @var string
      */
    protected static $swaggerModelName = 'ControlResponse';

    /**
      * Array of property to type mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerTypes = [
        'efs_code' => 'string',
        'external_direct_debit_id' => 'string',
        'external_transfer_id' => 'string',
        'messages' => '\Swagger\Server\Model\ErrorMessage[]',
        'status' => 'string'
    ];

    /**
      * Array of property to format mappings. Used for (de)serialization
      *
      * @var string[]
      */
    protected static $swaggerFormats = [
        'efs_code' => null,
        'external_direct_debit_id' => null,
        'external_transfer_id' => null,
        'messages' => null,
        'status' => null
    ];

    /**
     * Array of property to type mappings. Used for (de)serialization
     *
     * @return array
     */
    public static function swaggerTypes()
    {
        return self::$swaggerTypes;
    }

    /**
     * Array of property to format mappings. Used for (de)serialization
     *
     * @return array
     */
    public static function swaggerFormats()
    {
        return self::$swaggerFormats;
    }

    /**
     * Array of attributes where the key is the local name,
     * and the value is the original name
     *
     * @var string[]
     */
    protected static $attributeMap = [
        'efs_code' => 'efsCode',
        'external_direct_debit_id' => 'externalDirectDebitId',
        'external_transfer_id' => 'externalTransferId',
        'messages' => 'messages',
        'status' => 'status'
    ];

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @var string[]
     */
    protected static $setters = [
        'efs_code' => 'setEfsCode',
        'external_direct_debit_id' => 'setExternalDirectDebitId',
        'external_transfer_id' => 'setExternalTransferId',
        'messages' => 'setMessages',
        'status' => 'setStatus'
    ];

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @var string[]
     */
    protected static $getters = [
        'efs_code' => 'getEfsCode',
        'external_direct_debit_id' => 'getExternalDirectDebitId',
        'external_transfer_id' => 'getExternalTransferId',
        'messages' => 'getMessages',
        'status' => 'getStatus'
    ];

    /**
     * Array of attributes where the key is the local name,
     * and the value is the original name
     *
     * @return array
     */
    public static function attributeMap()
    {
        return self::$attributeMap;
    }

    /**
     * Array of attributes to setter functions (for deserialization of responses)
     *
     * @return array
     */
    public static function setters()
    {
        return self::$setters;
    }

    /**
     * Array of attributes to getter functions (for serialization of requests)
     *
     * @return array
     */
    public static function getters()
    {
        return self::$getters;
    }

    /**
     * The original name of the model.
     *
     * @return string
     */
    public function getModelName()
    {
        return self::$swaggerModelName;
    }

    

    

    /**
     * Associative array for storing property values
     *
     * @var mixed[]
     */
    protected $container = [];

    /**
     * Constructor
     *
     * @param mixed[] $data Associated array of property values
     *                      initializing the model
     */
    public function __construct(array $data = null)
    {
        $this->container['efs_code'] = isset($data['efs_code']) ? $data['efs_code'] : null;
        $this->container['external_direct_debit_id'] = isset($data['external_direct_debit_id']) ? $data['external_direct_debit_id'] : null;
        $this->container['external_transfer_id'] = isset($data['external_transfer_id']) ? $data['external_transfer_id'] : null;
        $this->container['messages'] = isset($data['messages']) ? $data['messages'] : null;
        $this->container['status'] = isset($data['status']) ? $data['status'] : null;
    }

    /**
     * Show all the invalid properties with reasons.
     *
     * @return array invalid properties with reasons
     */
    public function listInvalidProperties()
    {
        $invalidProperties = [];

        return $invalidProperties;
    }

    /**
     * Validate all the properties in the model
     * return true if all passed
     *
     * @return bool True if all properties are valid
     */
    public function valid()
    {
        return count($this->listInvalidProperties()) === 0;
    }


    /**
     * Gets efs_code
     *
     * @return string
     */
    public function getEfsCode()
    {
        return $this->container['efs_code'];
    }

    /**
     * Sets efs_code
     *
     * @param string $efs_code efs_code
     *
     * @return $this
     */
    public function setEfsCode($efs_code)
    {
        $this->container['efs_code'] = $efs_code;

        return $this;
    }

    /**
     * Gets external_direct_debit_id
     *
     * @return string
     */
    public function getExternalDirectDebitId()
    {
        return $this->container['external_direct_debit_id'];
    }

    /**
     * Sets external_direct_debit_id
     *
     * @param string $external_direct_debit_id external_direct_debit_id
     *
     * @return $this
     */
    public function setExternalDirectDebitId($external_direct_debit_id)
    {
        $this->container['external_direct_debit_id'] = $external_direct_debit_id;

        return $this;
    }

    /**
     * Gets external_transfer_id
     *
     * @return string
     */
    public function getExternalTransferId()
    {
        return $this->container['external_transfer_id'];
    }

    /**
     * Sets external_transfer_id
     *
     * @param string $external_transfer_id external_transfer_id
     *
     * @return $this
     */
    public function setExternalTransferId($external_transfer_id)
    {
        $this->container['external_transfer_id'] = $external_transfer_id;

        return $this;
    }

    /**
     * Gets messages
     *
     * @return \Swagger\Server\Model\ErrorMessage[]
     */
    public function getMessages()
    {
        return $this->container['messages'];
    }

    /**
     * Sets messages
     *
     * @param \Swagger\Server\Model\ErrorMessage[] $messages messages
     *
     * @return $this
     */
    public function setMessages($messages)
    {
        $this->container['messages'] = $messages;

        return $this;
    }

    /**
     * Gets status
     *
     * @return string
     */
    public function getStatus()
    {
        return $this->container['status'];
    }

    /**
     * Sets status
     *
     * @param string $status status
     *
     * @return $this
     */
    public function setStatus($status)
    {
        $this->container['status'] = $status;

        return $this;
    }
    /**
     * Returns true if offset exists. False otherwise.
     *
     * @param integer $offset Offset
     *
     * @return boolean
     */
    #[\ReturnTypeWillChange]
    public function offsetExists($offset)
    {
        return isset($this->container[$offset]);
    }

    /**
     * Gets offset.
     *
     * @param integer $offset Offset
     *
     * @return mixed
     */
    #[\ReturnTypeWillChange]
    public function offsetGet($offset)
    {
        return isset($this->container[$offset]) ? $this->container[$offset] : null;
    }

    /**
     * Sets value based on offset.
     *
     * @param integer $offset Offset
     * @param mixed   $value  Value to be set
     *
     * @return void
     */
    #[\ReturnTypeWillChange]
    public function offsetSet($offset, $value)
    {
        if (is_null($offset)) {
            $this->container[] = $value;
        } else {
            $this->container[$offset] = $value;
        }
    }

    /**
     * Unsets offset.
     *
     * @param integer $offset Offset
     *
     * @return void
     */
    #[\ReturnTypeWillChange]
    public function offsetUnset($offset)
    {
        unset($this->container[$offset]);
    }

    /**
     * Gets the string presentation of the object
     *
     * @return string
     */
    public function __toString()
    {
        if (defined('JSON_PRETTY_PRINT')) { // use JSON pretty print
            return json_encode(
                ObjectSerializer::sanitizeForSerialization($this),
                JSON_PRETTY_PRINT
            );
        }

        return json_encode(ObjectSerializer::sanitizeForSerialization($this));
    }
}


